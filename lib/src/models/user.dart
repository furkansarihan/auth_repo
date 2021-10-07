import 'package:equatable/equatable.dart';
import 'package:firebase_auth/firebase_auth.dart';

/// {@template user}
/// User model
///
/// [User.empty] represents an unauthenticated user.
/// {@endtemplate}
class User extends Equatable {
  /// {@macro user}
  const User({
    required this.uid,
    this.displayName,
    this.email,
    this.emailVerified,
    this.isAnonymous,
    this.metadata,
    this.phoneNumber,
    this.photoURL,
    this.providerData,
    this.refreshToken,
    this.tenantId,
  });

  final String uid;

  final String? displayName;

  final String? email;

  final bool? emailVerified;

  final bool? isAnonymous;

  final UserMetadata? metadata;

  final String? phoneNumber;

  final String? photoURL;

  final List<UserInfo>? providerData;

  final String? refreshToken;

  final String? tenantId;

  /// Empty user which represents an unauthenticated user.
  static const empty = User(
    uid: '',
    displayName: null,
    email: null,
    emailVerified: null,
    isAnonymous: null,
    metadata: null,
    phoneNumber: null,
    photoURL: null,
    providerData: null,
    refreshToken: null,
    tenantId: null,
  );

  @override
  List<Object> get props => [
        uid,
        if (displayName != null) displayName!,
        if (email != null) email!,
        if (emailVerified != null) emailVerified!,
        if (isAnonymous != null) isAnonymous!,
        if (metadata != null) metadata!,
        if (phoneNumber != null) phoneNumber!,
        if (photoURL != null) photoURL!,
        if (providerData != null) providerData!,
        if (refreshToken != null) refreshToken!,
        if (tenantId != null) tenantId!,
      ];
}
