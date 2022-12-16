/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
import { constants as securityConstants } from '@digitalbazaar/security-context'

export const constants = {
  SECURITY_CONTEXT_URL: securityConstants.SECURITY_CONTEXT_V2_URL,
  SECURITY_CONTEXT_V1_URL: securityConstants.SECURITY_CONTEXT_V1_URL,
  SECURITY_CONTEXT_V2_URL: securityConstants.SECURITY_CONTEXT_V2_URL,
  SECURITY_PROOF_URL: 'https://w3id.org/security#proof',
  SECURITY_SIGNATURE_URL: 'https://w3id.org/security#signature'
}
