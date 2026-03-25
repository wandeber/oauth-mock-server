export const STANDARD_PROFILE_CLAIMS = new Set([
  "name",
  "family_name",
  "given_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "updated_at"
]);

export const STANDARD_EMAIL_CLAIMS = new Set(["email", "email_verified"]);
export const STANDARD_PHONE_CLAIMS = new Set(["phone_number", "phone_number_verified"]);
export const STANDARD_ADDRESS_CLAIMS = new Set(["address"]);

export const ALL_STANDARD_SCOPE_CLAIMS = new Set([
  ...STANDARD_PROFILE_CLAIMS,
  ...STANDARD_EMAIL_CLAIMS,
  ...STANDARD_PHONE_CLAIMS,
  ...STANDARD_ADDRESS_CLAIMS,
  "sub"
]);
