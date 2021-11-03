import 'dart:async';
import 'dart:convert';
import 'dart:developer';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart' as firebase_auth;
import 'package:firebase_auth_oauth/firebase_auth_oauth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

import 'models/models.dart';

/// Thrown if during the sign up process if a failure occurs.
class SignUpFailure implements Exception {
  SignUpFailure({
    this.code,
    this.message,
    this.email,
  });
  String? code;
  String? message;
  String? email;
}

/// Thrown during the login process if a failure occurs.
class SignInWithEmailAndPasswordFailure implements Exception {
  SignInWithEmailAndPasswordFailure({
    this.code,
    this.message,
    this.email,
  });
  String? code;
  String? message;
  String? email;
}

class PasswordResetFailure implements Exception {
  PasswordResetFailure({
    this.code,
    this.message,
    this.email,
  });
  String? code;
  String? message;
  String? email;
}

/// Thrown during the login process if a failure occurs.
class VerifyWithPhoneFailure implements Exception {}

/// Thrown during the sign in with google process if a failure occurs.
class LogInWithGoogleFailure implements Exception {}

/// Thrown during the sign in with apple process if a failure occurs.
class LogInWithAppleFailure implements Exception {}

/// Thrown during the sign in with facebook process if a failure occurs.
class LogInWithFacebookFailure implements Exception {}

class AccountExistDifferentProviderException implements Exception {
  AccountExistDifferentProviderException({
    this.code,
    this.email,
    this.message,
  });
  String? code;
  String? message;
  String? email;
}

/// Thrown during the logout process if a failure occurs.
class LogOutFailure implements Exception {}

/// Thrown during the delete process if a failure occurs.
class DeleteUserFailure implements Exception {}

class RecentLoginRequiredFailure implements Exception {}

/// {@template authentication_repository}
/// Repository which manages user authentication.
/// {@endtemplate}
class AuthRepo {
  /// {@macro authentication_repository}
  AuthRepo({
    firebase_auth.FirebaseAuth? firebaseAuth,
    GoogleSignIn? googleSignIn,
    FacebookAuth? facebookAuth,
  })  : _firebaseAuth = firebaseAuth ?? firebase_auth.FirebaseAuth.instance,
        _googleSignIn = googleSignIn ?? GoogleSignIn.standard(),
        _facebookAuth = facebookAuth ?? FacebookAuth.instance;

  late final firebase_auth.FirebaseAuth _firebaseAuth;
  late final GoogleSignIn _googleSignIn;
  late final FacebookAuth _facebookAuth;

  bool? get guest => _firebaseAuth.currentUser?.isAnonymous;
  String? get uid => _firebaseAuth.currentUser?.uid;
  User? get currentUser => _firebaseAuth.currentUser?.toUser;

  /// Stream of [User] which will emit the current user when
  /// the authentication state changes.
  ///
  /// Emits [User.empty] if the user is not authenticated.
  Stream<User> get user {
    return _firebaseAuth.authStateChanges().map((firebaseUser) {
      return firebaseUser == null ? User.empty : firebaseUser.toUser;
    });
  }

  /// Stream of [User] which will emit the current user when
  /// any user updates.
  ///
  /// Emits [User.empty] if the user is not authenticated.
  Stream<User> get userChanges {
    return _firebaseAuth.userChanges().map((firebaseUser) {
      return firebaseUser == null ? User.empty : firebaseUser.toUser;
    });
  }

  Future<void> reloadUser() async {
    return _firebaseAuth.currentUser?.reload();
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
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException) {
        throw SignUpFailure(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw SignUpFailure();
    }
  }

  Future<void> sendPasswordResetEmail({
    required String email,
  }) async {
    try {
      await _firebaseAuth.sendPasswordResetEmail(email: email);
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException) {
        throw PasswordResetFailure(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw PasswordResetFailure();
    }
  }

  Future<void>? sendEmailVerification() async {
    await _firebaseAuth.currentUser?.sendEmailVerification();
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
  Future<void> signInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException) {
        throw SignInWithEmailAndPasswordFailure(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw SignInWithEmailAndPasswordFailure();
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
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException &&
          e.code == 'account-exists-with-different-credential') {
        throw AccountExistDifferentProviderException(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw LogInWithGoogleFailure();
    }
  }

  /// Returns the sha256 hash of [input] in hex notation.
  String _sha256ofString(String input) {
    final bytes = utf8.encode(input);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  Future<void> signInWithApple() async {
    if (kIsWeb || Platform.isAndroid) {
      return _signInWithAppleOnAndroid();
    }
    // To prevent replay attacks with the credential returned from Apple, we
    // include a nonce in the credential request. When signing in with
    // Firebase, the nonce in the id token returned by Apple, is expected to
    // match the sha256 hash of `rawNonce`.
    final rawNonce = generateNonce();
    final nonce = _sha256ofString(rawNonce);

    // Request credential for the currently signed in Apple account.
    AuthorizationCredentialAppleID appleCredential;
    try {
      appleCredential = await SignInWithApple.getAppleIDCredential(
        scopes: [AppleIDAuthorizationScopes.email],
        nonce: nonce,
      );
    } catch (e) {
      throw LogInWithAppleFailure();
    }

    // Create an `OAuthCredential` from the credential returned by Apple.
    final oauthCredential = firebase_auth.OAuthProvider("apple.com").credential(
      idToken: appleCredential.identityToken,
      rawNonce: rawNonce,
    );

    // Sign in the user with Firebase. If the nonce we generated earlier does
    // not match the nonce in `appleCredential.identityToken`, sign in will fail.
    try {
      await _firebaseAuth.signInWithCredential(oauthCredential);
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException &&
          e.code == 'account-exists-with-different-credential') {
        throw AccountExistDifferentProviderException(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw LogInWithAppleFailure();
    }
  }

  Future<void> _signInWithAppleOnAndroid() async {
    final rawNonce = generateNonce();

    firebase_auth.OAuthCredential appleCredential;
    try {
      appleCredential = await FirebaseAuthOAuth().signInOAuth(
        "apple.com",
        ["email"],
      );
    } catch (e) {
      throw LogInWithAppleFailure();
    }

    // Create an `OAuthCredential` from the credential returned by Apple.
    final oauthCredential = firebase_auth.OAuthProvider("apple.com").credential(
      idToken: appleCredential.idToken,
      rawNonce: rawNonce,
    );

    // Sign in the user with Firebase. If the nonce we generated earlier does
    // not match the nonce in `appleCredential.identityToken`, sign in will fail.
    try {
      await _firebaseAuth.signInWithCredential(oauthCredential);
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException && e.code == 'unknown') {
        return;
      } else if (e is firebase_auth.FirebaseAuthException &&
          e.code == 'account-exists-with-different-credential') {
        throw AccountExistDifferentProviderException(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw LogInWithAppleFailure();
    }
  }

  Future<void> signInWithFacebook() async {
    // Trigger the sign-in flow
    LoginResult loginResult;
    try {
      loginResult = await _facebookAuth.login(
        permissions: const ['email'],
      );
    } catch (e) {
      throw LogInWithFacebookFailure();
    }

    if (loginResult.accessToken == null) {
      throw LogInWithFacebookFailure();
    }

    // Create a credential from the access token
    final firebase_auth.OAuthCredential facebookAuthCredential =
        firebase_auth.FacebookAuthProvider.credential(
      loginResult.accessToken!.token,
    );

    try {
      await _firebaseAuth.signInWithCredential(facebookAuthCredential);
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException &&
          e.code == 'account-exists-with-different-credential') {
        throw AccountExistDifferentProviderException(
          code: e.code,
          message: e.message,
          email: e.email,
        );
      }
      throw LogInWithFacebookFailure();
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

  /// Deletes current user.
  Future<void> deleteUser() async {
    try {
      await _firebaseAuth.currentUser?.delete();
    } catch (e) {
      if (e is firebase_auth.FirebaseAuthException &&
          e.code == 'requires-recent-login') {
        throw RecentLoginRequiredFailure();
      }
      throw DeleteUserFailure();
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
