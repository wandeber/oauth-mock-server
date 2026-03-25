import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_DIR = path.resolve(__dirname, "../..");

export const TEST_RSA_KEY_ID = "dev-test-rs256";

export const TEST_RSA_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDS3FXnBjJpXPrX
4Yg/Zlr3h5dxnmc29+E86KmPDF2Q0T64DNbnPqnvXxljZLGiYpcq3fHZjh+GR+ja
AJZ0ZOWaw2tCZGuKuH0hQ1/LsVBnuwbA9aucGq4AW+RL6TO0mTL8QIAwMNHWzeL7
+f+DdVa1YWaWZflMpX52Lt+uXUkY6E4FQ+yyggE9z5E5Ula/pHcObIC3b70N51hk
QKSyWyBYEMFjrc++nUwTnHE5CIeLbzNnEK+NKXbjosVyqXgwM1jYmB+6iAYwk7ty
BFLQ1X8iLeBplK+qObYQruM5/+4DyLIpFrhO2qAb9KY69fNqQQkE+HsoYHDBuVfN
DLjLoImFAgMBAAECggEAF06+pL+acUC+A4CNAGu5JhT+qFL47WpfTc3D9v7IFZAO
ODxHFvQ7cYJYD+oF+UFKR1/qx1WpO2fAdTR3wlw9cFV7NNwHx84rxVz+qPPWbkON
9A9TzaNkqhUo5OaH+MWvDT4N+AW1dDfO3XPICskSHBDXokvu+h9tnUpXdEfLIthQ
xlVccV/WMDf/yg3ZaxrqaOMErlLxUviWDYJuIUvCAvK7ky555jQu2RaRaN7b1LuO
vn/WDBXgCOkuAXdTOQvHXbD3KAx0+h5ZUHlxVx8JE/4g+L2drmM43jklfsraxRtk
Y2Eqkl3Gb2ZWSNi4qeR5tY5jnc+x+zKZzA7CuspNowKBgQDo3BeAdJt8Hx4PzaDP
qmwfqbCqTzeWMHA/pgbsPjuzyMLQP5e6lKbbHHzUX3wqeqkczIPSxXnfJjFArzY+
jYwa5h/8MFgmsxNMFoo6wOOTsUHDwBU7HkOPBKTFFGgmaeS9aM5rcs6ceAD6B6x1
e9JzfiQ0rfVjXpP5ZstqYqrrUwKBgQDn0JeSb0hM2Mlh64/bTv+76OvFrgVV1tqp
roMYuGCvFWmR9wKFEc/EXHRa6+0/3FXAxozRzeD69hD1Vf0Cn5KnhFSF0QH/GR3D
/nrQLlK0n6+VcuJ0JuhnEK4fifvf5Fr1pgYWv7RqmYRs8X3wsKYjkdz67zmyfmyz
RAuNPxZ0xwKBgQC+XG66DJmvdqDUun1kRyXtHIPYNrpyhVa+MbQnHRkheFYKeHJJ
jYx6Q2epFgYjk/L8IBUEEXv3+Pj6sEHgEUcgFlC/kaX+vRZhdWu7bESfUKE6raSt
l6gTGvC4TF54SMk+LpfRLyHIuDHUNMG/qWH6GHzws+WPPpopoOdaKR8hEQKBgEbr
iBOivAnWoPW2LZK4voBsqAUYUkWKr+cNnsnnTp0B/gRL/5dadafraSWP3EuXSxzp
IZfmVpgww8tq/TbaPvHFCF7QLL4wnuyhZE1gfqkH2Z3tQd6rMJqnfb3kZwx+Pl28
50v6ZmXehacW0qLaSFnFfEfA/HPhPbwyax5RWLttAoGAM2bm/D+aFFI8HFst3CTz
+hygaSZ+9uVHZ1VmQSG0jy8y8JjxLxT6GyX7Hesbp7md4N+NDQE/BPWpQxeT++tR
D7/ZkKTeOOKyU5CEeDomoFGoMs6B4W92o4DyQBLdLWiez60RX78nyoSbtRFG7Nrj
Ibo+3NGxNrNAhgTcxlOapCw=
-----END PRIVATE KEY-----`;

export const TEST_PUBLIC_CLIENT_ID = "public-web";
export const TEST_EMAIL_ONLY_CLIENT_ID = "email-only-web";
export const TEST_CONFIDENTIAL_CLIENT_ID = "confidential-web";
export const TEST_DOCKER_CLIENT_ID = "docker-app";

export const TEST_PUBLIC_REDIRECT_URI = "http://localhost/public/callback";
export const TEST_EMAIL_ONLY_REDIRECT_URI = "http://localhost/email-only/callback";
export const TEST_CONFIDENTIAL_REDIRECT_URI = "http://localhost/confidential/callback";
export const TEST_DOCKER_REDIRECT_URI = "http://localhost:3000/callback";

export const TEST_CONFIDENTIAL_CLIENT_SECRET = "confidential-secret";

export const TEST_STANDARD_SCOPES = {
  openidProfileEmail: "openid email profile",
  openidEmail: "openid email",
  openidEmailProfileOfflineAccess: "openid email profile offline_access"
} as const;
