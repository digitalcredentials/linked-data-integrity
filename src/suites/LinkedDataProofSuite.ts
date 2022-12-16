/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
import { DocumentLoader, Proof, VerificationResult } from '../types'

export abstract class LinkedDataProofSuite {
  type: string

  constructor({ type }: { type: string }) {
    this.type = type
  }

  /**
   * @param document {object} to be signed.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  abstract createProof(
    {
      /* document, purpose, documentLoader */
    }
  ): Promise<Proof>

  /**
   * @param proof {object} the proof to be verified.
   * @param document {object} the document the proof applies to.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  abstract verifyProof(
    {
      /* proof, document, purpose, documentLoader */
    }
  ): Promise<VerificationResult>

  /**
   * Checks whether a given proof exists in the document.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.proof
   *
   * @returns {Promise<boolean>} Whether a match for the proof was found.
   */
  async matchProof({
    proof,
    document,
    documentLoader
  }: {
    proof: Proof
    document: any
    documentLoader: DocumentLoader
  }): Promise<boolean> {
    return proof.type === this.type
  }
}
