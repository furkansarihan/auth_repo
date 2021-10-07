import 'dart:async';
import 'dart:developer';

import 'package:firebase_auth/firebase_auth.dart' as firebase_auth;
import 'package:google_sign_in/google_sign_in.dart';

import 'models/models.dart';

/// Thrown if during the sign up process if a failure occurs.
class SignUpFailure implements Exception {}

/// Thrown during the login process if a failure occurs.
class LogInWithEmailAndPasswordFailure implements Exception {}

/// Thrown during the login process if a failure occurs.
class VerifyWithPhoneFailure implements Exception {}

/// Thrown during the sign in with google process if a failure occurs.
class LogInWithGoogleFailure implements Exception {}

/// Thrown during the logout process if a failure occurs.
class LogOutFailure implements Exception {}

/// {@template authentication_repository}
/// Repository which manages user authentication.
/// {@endtemplate}
class AuthRepo {
  /// {@macro authentication_repository}
  AuthRepo({
    firebase_auth.FirebaseAuth? firebaseAuth,
    GoogleSignIn? googleSignIn,
  })  : _firebaseAuth = firebaseAuth ?? firebase_auth.FirebaseAuth.instance,
        _googleSignIn = googleSignIn ?? GoogleSignIn.standard();

  late final firebase_auth.FirebaseAuth _firebaseAuth;
  late final GoogleSignIn _googleSignIn;

  bool? get guest => _firebaseAuth.currentUser?.isAnonymous;
  String? get uid => _firebaseAuth.currentUser?.uid;

  /// Stream of [User] which will emit the current user when
  /// the authentication state changes.
  ///
  /// Emits [User.empty] if the user is not authenticated.
  Stream<User> get user {
    return _firebaseAuth.authStateChanges().map((firebaseUser) {
      return firebaseUser == null ? User.empty : firebaseUser.toUser;
    });
  }

  /// Creates a new user with the provided [email] and [password].
  ///
  /// Throws a [SignUpFailure] if an exception occurs.
  Future<void> signUp({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on Exception {
      throw SignUpFailure();
    }
  }

  /// Creates an new anonymous user.
  ///
  /// Throws a [SignUpFailure] if an exception occurs.
  Future<void> signInAnonymous() async {
    try {
      await _firebaseAuth.signInAnonymously();
    } on Exception {
      throw SignUpFailure();
    }
  }

  /// Signs in with the provided [email] and [password].
  ///
  /// Throws a [LogInWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> logInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on Exception {
      throw LogInWithEmailAndPasswordFailure();
    }
  }

  /// Sends phone verification code to specified [phoneNumber].
  ///
  /// Throws a [VerifyWithPhoneFailure] if an exception occurs.
  Future<void> verifyPhoneNumber({
    required String phoneNumber,
    int? forceResendingToken,
    Function(String verificationID, int? forceResendingToken)? codeSentCallback,
    Function(String verificationID)? codeTimeoutCallback,
    Function? codeSuccessCallback,
    Function? codeVerificationFailedCallback,
    Duration? timeout,
  }) async {
    final firebase_auth.PhoneVerificationCompleted verificationCompleted = (
      firebase_auth.AuthCredential credential,
    ) async {
      _firebaseAuth.signInWithCredential(credential).then((v) async {
        codeSuccessCallback?.call();
      });
    };

    final firebase_auth.PhoneVerificationFailed verificationFailed = (
      firebase_auth.FirebaseAuthException authException,
    ) {
      log("Code: ${authException.code}. Message: ${authException.message}");
      codeVerificationFailedCallback?.call();
    };

    final firebase_auth.PhoneCodeSent codeSent = (
      String _verificationID, [
      int? forceResendingToken,
    ]) {
      codeSentCallback?.call(_verificationID, forceResendingToken);
    };

    final firebase_auth.PhoneCodeAutoRetrievalTimeout codeAutoRetrievalTimeout =
        (String _verificationID) {
      codeTimeoutCallback?.call(_verificationID);
    };
    try {
      await _firebaseAuth.verifyPhoneNumber(
        phoneNumber: phoneNumber,
        forceResendingToken: forceResendingToken,
        timeout: timeout ?? const Duration(seconds: 30),
        codeSent: codeSent,
        verificationCompleted: verificationCompleted,
        verificationFailed: verificationFailed,
        codeAutoRetrievalTimeout: codeAutoRetrievalTimeout,
      );
    } on Exception {
      throw VerifyWithPhoneFailure();
    }
  }

  /// Signs in with the provided [email] and [password].
  ///
  /// Throws a [LogInWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> signInWithSmsCode({
    required String verificationID,
    required String smsCode,
  }) async {
    firebase_auth.AuthCredential credential =
        firebase_auth.PhoneAuthProvider.credential(
      verificationId: verificationID,
      smsCode: smsCode,
    );
    try {
      await _firebaseAuth.signInWithCredential(credential);
    } on Exception {
      throw VerifyWithPhoneFailure();
    }
  }

  Future<void> signInWithGoogle() async {
    // Trigger the authentication flow
    final GoogleSignInAccount? googleUser;

    try {
      googleUser = await _googleSignIn.signIn();
    } catch (e) {
      throw LogInWithGoogleFailure();
    }

    if (googleUser == null) {
      throw LogInWithGoogleFailure();
    }

    // Obtain the auth details from the request
    final GoogleSignInAuthentication googleAuth =
        await googleUser.authentication;

    // Create a new credential
    final credential = firebase_auth.GoogleAuthProvider.credential(
      accessToken: googleAuth.accessToken,
      idToken: googleAuth.idToken,
    );

    // Once signed in, return the UserCredential
    try {
      await _firebaseAuth.signInWithCredential(credential);
    } on Exception {
      throw LogInWithGoogleFailure();
    }
  }

  /// Signs out the current user which will emit
  /// [User.empty] from the [user] Stream.
  ///
  /// Throws a [LogOutFailure] if an exception occurs.
  Future<void> signOut() async {
    try {
      await Future.wait([
        _firebaseAuth.signOut(),
        _googleSignIn.signOut(),
      ]);
    } on Exception {
      throw LogOutFailure();
    }
  }
}

extension on firebase_auth.User {
  User get toUser {
    return User(
      uid: uid,
      displayName: displayName,
      email: email,
      emailVerified: emailVerified,
      isAnonymous: isAnonymous,
      metadata: metadata,
      phoneNumber: phoneNumber,
      photoURL: photoURL,
      providerData: providerData,
      refreshToken: refreshToken,
      tenantId: tenantId,
    );
  }
}
