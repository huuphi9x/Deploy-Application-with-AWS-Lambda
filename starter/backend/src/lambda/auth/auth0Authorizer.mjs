import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'dev-fhtksn76juyr55wz.us.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJVtJASOmukTywMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1maHRrc243Nmp1eXI1NXd6LnVzLmF1dGgwLmNvbTAeFw0yNDA5MTIx
NTU4NTJaFw0zODA1MjIxNTU4NTJaMCwxKjAoBgNVBAMTIWRldi1maHRrc243Nmp1
eXI1NXd6LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANuN2aX+KjJk6MwSu7HWV9swBuFPOnVd+fXxBrN1ru0Aew5QMeYUjDguZnxT
G6zYBx4SwF2CQiPLrEH4LU97iQAERmMnJIEpeHXZ4zFNDBz8iohBaqMK88zxeDZN
a3vGtB2i9q2RRa1TM5SxVJ+AEt+u7GJvoPpOoTaO3GkljSurcxrG0PINo9kpU+lW
9Sif2FRmwXprZp20QYc5DkHvYRp2LrAR76diQg2un88N7PfCD1udtliVPqX73LqP
ukkkzTp1mYcgYeFzQScwfEcnrqzQM5IHZBZfNQoACH0u5rSCiD3OX3O1AqSWHNs5
skcDhV1BFr8fZxa5F0xHEd0GXOsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQU9p9d2C7eiiFqOXhBntXgjmqk3+8wDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBV2P5wsJn/O0HF5wZ5Ie74PWD9m/utPbfwacn0wr4n
v8S1FivvwQlkdpvDJ/Alji1NjFmYsH2xpLBHNkV9vy20QnDgA/9kIbo3nSzKwUsx
gBkqp9jOJs+KS9dNBgrxUrS0fBWWXf9XVYHjAdGYOjIL1vHxwsGW5AnmRk6ULE4+
6dqwYBdNnt4MoiXKFn0+OMxp5uN4P11Sh+rwJwpPHqw5ugeki4L0PJuY/fSz5h5r
smYJsrJVYNoUIKzff17XLluCTnKckkOQEqrvvW4KanliqAC6BNRjUPTOdxQWBi8/
PXGQeYJoiNmjNa0BkBbae4UYKptn41KRBOxeSq2oslYm
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
  return jwt;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
