/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
import * as jsonld from 'jsonld'

import { constants } from '../constants'
import { ProofPurpose } from './ProofPurpose'
import {
  Controller,
  DateType,
  DocumentLoader,
  Proof,
  ValidationResult,
  VerificationMethodObject
} from '../types'

// DID documents can be specially optimized
const DID_CONTEXT_V1 = 'https://www.w3.org/ns/did/v1'

// verification relationship terms that are known to appear in DID documents
const DID_VR_TERMS = [
  'assertionMethod',
  'authentication',
  'capabilityInvocation',
  'capabilityDelegation',
  'keyAgreement',
  'verificationMethod'
]

export class ControllerProofPurpose extends ProofPurpose {
  controller?: Controller
  _termDefinedByDIDContext: boolean

  /**
   * Creates a proof purpose that will validate whether or not the verification
   * method in a proof was authorized by its declared controller for the
   * proof's purpose.
   *
   * @param term {string} the `proofPurpose` term, as defined in the
   *    SECURITY_CONTEXT_URL `@context` or a URI if not defined in such.
   * @param [controller] {object} the description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param [date] {string or Date or integer} the expected date for
   *   the creation of the proof.
   * @param [maxTimestampDelta] {number} An integer maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   */
  constructor({
    term,
    controller,
    date = new Date(),
    maxTimestampDelta = Infinity
  }: {
    term: string
    controller?: Controller
    date?: DateType
    maxTimestampDelta?: number
  }) {
    super({ term, date, maxTimestampDelta })
    if (controller) {
      this.controller = controller
    }
    this._termDefinedByDIDContext = DID_VR_TERMS.includes(term)
  }

  /**
   * Validates the purpose of a proof. This method is called during
   * proof verification, after the proof value has been checked against the
   * given verification method (e.g. in the case of a digital signature, the
   * signature has been cryptographically verified against the public key).
   *
   * @param proof
   * @param verificationMethod
   * @param documentLoader
   *
   * @throws {Error} If verification method not authorized by controller
   * @throws {Error} If proof's created timestamp is out of range
   *
   * @returns {Promise<{valid: boolean, error: Error}>}
   */
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
      const result = await super.validate(proof, {
        verificationMethod,
        documentLoader
      })
      if (!result.valid) {
        throw result.error as Error
      }

      const { id: verificationId } = verificationMethod
      const { term, _termDefinedByDIDContext } = this

      if (this.controller) {
        result.controller = this.controller
      } else {
        // if no `controller` specified in proof purpose, use verification method's
        const { controller } = verificationMethod

        // controllerId must be a string representing a URL (will be fetched via documentLoader)
        const controllerId =
          typeof controller === 'string' ? controller : controller.id

        // apply optimization to controller documents that are DID documents;
        // if `term` is one of those defined by the DID context
        let { document } = await documentLoader(controllerId)
        const mustFrame = !(
          (_termDefinedByDIDContext &&
            document['@context'] === DID_CONTEXT_V1) ||
          (Array.isArray(document['@context']) &&
            document['@context'][0] === DID_CONTEXT_V1)
        )
        if (mustFrame) {
          document = await jsonld.frame(
            document,
            {
              '@context': constants.SECURITY_CONTEXT_URL,
              id: controllerId,
              // this term must be in the JSON-LD controller document or
              // verification will fail
              [term]: {
                '@embed': '@never',
                id: verificationId
              }
            },
            { documentLoader, compactToRelative: false }
          )
        }
        result.controller = document
      }

      const verificationMethods = jsonld.getValues(result.controller, term)
      result.valid = verificationMethods.some(
        (vm: any) =>
          vm === verificationId ||
          (typeof vm === 'object' && vm.id === verificationId)
      )
      if (!result.valid) {
        throw new Error(
          `Verification method "${verificationMethod.id}" not authorized ` +
            `by controller for proof purpose "${this.term}".`
        )
      }
      return result
    } catch (error: any) {
      return { valid: false, error }
    }
  }
}
