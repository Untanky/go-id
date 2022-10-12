package auth_test

import (
	"testing"
	"time"

	. "github.com/Untanky/go-id/auth"
	jwt "github.com/Untanky/go-id/jwt"
	. "github.com/Untanky/go-id/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	rsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
	rsaPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`
	ecdsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`
	psaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
)

type RefreshTokenTestSuite struct {
	suite.Suite
	service TokenService[*RefreshTokenPayload]
}

func (suite *RefreshTokenTestSuite) SetupTest() {
	secret := NewSecretValue("key")

	jwtService := new(jwt.JwtService[SecretString])
	jwtService.Init(jwt.HS256, secret)

	refreshToken := new(RefreshTokenService)
	refreshToken.Init(jwtService)
	suite.service = refreshToken
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_CreateAndValidateJwt() {
	sub := "123"
	sid := "abc"
	payload := &RefreshTokenPayload{
		Sid: sid,
		Sub: sub,
	}

	tokenString, err := suite.service.Create(payload)
	assert.Nil(suite.T(), err)

	payloadMap, err := tokenString.Payload()

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payloadMap["sid"])
	assert.Equal(suite.T(), sub, payloadMap["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payloadMap["iat"])
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), payloadMap["exp"])

	validatedPayload, err := suite.service.Validate(tokenString)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), payload.Sid, validatedPayload.Sid)
	assert.Equal(suite.T(), payload.Sub, validatedPayload.Sub)
	assert.Equal(suite.T(), time.Now().Unix(), validatedPayload.Iat)
	assert.Equal(suite.T(), time.Now().AddDate(1, 0, 0).Unix(), validatedPayload.Exp)
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseOfWrongSecret() {
	fakeTokenString := jwt.Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.-Msx6dR3kerkZ8g0jyJgpZ1oki3Z-lWmbifP42m-eGg")

	payload, err := suite.service.Validate(fakeTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "signature")
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItExpired() {
	expiredTokenString := jwt.Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.UoWNJ5MjP4013Wll-m8WeLu2MR6pczHD2usf_A58Yww")

	payload, err := suite.service.Validate(expiredTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "expired")
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItWasIssuedInTheFuture() {
	futureTokenString := jwt.Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTcxNzIzOTAyMiwiZXhwIjoxNzE2Mjc4OTMxfQ.eMy2GxxPi1MXxz46u_aJ24Bb4N-RDdHjqc_kPDwn8Nw")

	payload, err := suite.service.Validate(futureTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "before issued")
}

type AccessTokenTestSuite struct {
	suite.Suite
	service *AccessTokenService
}

func (suite *AccessTokenTestSuite) SetupTest() {
	secret := NewSecretPair(KeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  rsaPublicKey,
	})

	jwtService := new(jwt.JwtService[KeyPair])
	jwtService.Init(jwt.RS256, secret)

	accessToken := new(AccessTokenService)
	accessToken.Init(jwtService)
	suite.service = accessToken
}

func (suite *AccessTokenTestSuite) TestAccessToken_CreateAndValidateJwt() {
	sub := "123"
	sid := "abc"
	payload := &RefreshTokenPayload{
		Sid: sid,
		Sub: sub,
	}

	token, err := suite.service.Create(payload)
	assert.Nil(suite.T(), err)

	payloadMap, err := token.Payload()
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payloadMap["sid"])
	assert.Equal(suite.T(), sub, payloadMap["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payloadMap["iat"])
	assert.Equal(suite.T(), float64(time.Now().Unix() + 60 * 60), payloadMap["exp"])

	validatedPayload, err := suite.service.Validate(token)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), payload.Sid, validatedPayload.Sid)
	assert.Equal(suite.T(), payload.Sub, validatedPayload.Sub)
	assert.Equal(suite.T(), time.Now().Unix(), validatedPayload.Iat)
	assert.Equal(suite.T(), time.Now().Unix() + 60 * 60, validatedPayload.Exp)
}

func (suite *AccessTokenTestSuite) TestAccessToken_ValidateJwtFailsBecauseOfWrongSecret() {
	fakeTokenString := jwt.Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.-Msx6dR3kerkZ8g0jyJgpZ1oki3Z-lWmbifP42m-eGg")

	payload, err := suite.service.Validate(fakeTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "signature")
}

func (suite *AccessTokenTestSuite) TestAccessToken_ValidateJwtFailsBecauseItExpired() {
	expiredTokenString := jwt.Jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.blIaVaSIiENR_SwTLlDrArVTgt3y5aTy2-FINrbq8xWmRKNs-cMHGR1LO0-LL2hM2ZAkHz-rtGp-xhv8jReHLYED_kHB5xvwsrIlql7BFGhn1uc_tqeR3wUcMhFfh0L0HhJ7G7rkzxGTME71arPg6krpGHAmXqm28ZZiKw0kboNJ9dgMyW32ZzVDP8tNqjV9FfHkzL5slVLjJZtEQ6CceArCBwagkWNnADOZOHzFTH7oHnlQ5BKY8n7iYrm_69lhDhS2CRjNqrkQUFuvBuwQmDj_rgEjndDDuGRoqs6toJg3rTXU3kpQGgQBwlyRVgthONMNeu6CSvwjC1EUGH28TA")

	payload, err := suite.service.Validate(expiredTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "expired")
}

func (suite *AccessTokenTestSuite) TestAccessToken_ValidateJwtFailsBecauseItWasIssuedInTheFuture() {
	futureTokenString := jwt.Jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTcxNzIzOTAyMiwiZXhwIjoxNzE2Mjc4OTMxfQ.Ew-_TGWMxYMkhaMtm7jSMDXiuOR1QXrlMeQU7czzvaxFqS9rZM3FKFDadpKiqnzG8kP-Am-2Yoyek65kXsg0sFAaeCVDV9Lo9wYQFukDnmb4guWwEbbZunAczpfPeCZNSEB9tp1ezI2frxLtQTLOVN0qi5tvRFicQ1rZm5fdWzkdHvOKPCW-AQTLoYrYUGhAWMR9a5s_vcRLO15xmCybjN8r0g2OKb2RDlBfxV1jYt2fjSrLLNPC4JfIdOFSaxdH4jVHEefhfPaqnWBmYeN_7jAEK295sGGD3Tvz15e5Ekt2MQZO7qZawWwZiz8RqgkIww5EhoDy2VnVXLFTlLGdXw")

	payload, err := suite.service.Validate(futureTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "before issued")
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(RefreshTokenTestSuite))
	suite.Run(t, new(AccessTokenTestSuite))
}
