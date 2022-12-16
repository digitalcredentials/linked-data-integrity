/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
import { ControllerProofPurpose } from './ControllerProofPurpose'
import {
  Controller,
  DateType,
  DocumentLoader,
  Proof,
  ValidationResult,
  VerificationMethodObject
} from '../types'
import { LinkedDataProofSuite } from '../suites/LinkedDataProofSuite'

export class AuthenticationProofPurpose extends ControllerProofPurpose {
  challenge: string
  domain?: string

  constructor({
    term = 'authentication',
    controller,
    challenge,
    date,
    domain,
    maxTimestampDelta = Infinity
  }: {
    term: string
    controller?: Controller
    challenge: string
    date: DateType
    domain?: string
    maxTimestampDelta?: number
  }) {
    super({ term, controller, date, maxTimestampDelta })

    this.challenge = challenge
    this.domain = domain
  }

  async validate(
    proof: Proof,
    {
      verificationMethod,
      documentLoader
    }: {
      verificationMethod: VerificationMethodObject
      documentLoader: DocumentLoader
    }
  ): Promise<ValidationResult> {
    try {
      // check challenge
      if (proof.challenge !== this.challenge) {
        throw new Error(
          'The challenge is not as expected; ' +
            `challenge="${proof.challenge as string}", expected="${
              this.challenge
            }"`
        )
      }

      // check domain
      if (this.domain !== undefined && proof.domain !== this.domain) {
        throw new Error(
          'The domain is not as expected; ' +
            `domain="${proof.domain as string}", expected="${this.domain}"`
        )
      }

      return super.validate(proof, {
        verificationMethod,
        documentLoader
      })
    } catch (error: any) {
      return { valid: false, error }
    }
  }

  async update(
    proof: Proof,
    {
      document,
      suite,
      documentLoader
    }: {
      document: any
      suite: LinkedDataProofSuite
      documentLoader: DocumentLoader
    }
  ): Promise<Proof> {
    proof = await super.update(proof, {
      document,
      suite,
      documentLoader
    })
    proof.challenge = this.challenge
    if (this.domain !== undefined) {
      proof.domain = this.domain
    }
    return proof
  }
}
