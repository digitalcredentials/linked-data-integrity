/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2010-2022 Digital Bazaar, Inc. All rights reserved.
 */
import { ProofSet } from './ProofSet'
import { VerificationError } from './VerificationError'
import { ProofPurpose } from './purposes/ProofPurpose'
import { DocumentLoader, VerificationResult } from './types'
import { LinkedDataSignature } from './suites/LinkedDataSignature'

/**
 * Cryptographically signs the provided document by adding a `proof` section,
 * based on the provided suite and proof purpose.
 *
 * @param {object} document - The JSON-LD document to be signed.
 *
 * @param {object} options - Options hashmap.
 * @param {LinkedDataSignature} options.suite - The linked data signature
 *   cryptographic suite, containing private key material, with which to sign
 *   the document.
 *
 * @param {ProofPurpose} purpose - A proof purpose instance that will
 *   match proofs to be verified and ensure they were created according to
 *   the appropriate purpose.
 *
 * @param {function} documentLoader  - A secure document loader (it is
 *   recommended to use one that provides static known documents, instead of
 *   fetching from the web) for returning contexts, controller documents, keys,
 *   and other relevant URLs needed for the proof.
 *
 * Advanced optional parameters and overrides:
 *
 * @param {boolean} [options.addSuiteContext=true] - Toggles the default
 *   behavior of each signature suite enforcing the presence of its own
 *   `@context` (if it is not present, it's added to the context list).
 *
 * @returns {Promise<object>} Resolves with signed document.
 */
export async function sign(
  document: object,
  {
    suite,
    purpose,
    documentLoader,
    addSuiteContext = true
  }: {
    suite: LinkedDataSignature
    purpose: ProofPurpose
    documentLoader: DocumentLoader
    addSuiteContext: boolean
  }
): Promise<object> {
  if (typeof document !== 'object') {
    throw new TypeError('The "document" parameter must be an object.')
  }
  // Ensure document contains the signature suite specific context URL
  // or throw an error (in case an advanced user overrides the `addSuiteContext`
  // flag to false).
  suite.ensureSuiteContext({ document, addSuiteContext })

  try {
    return await new ProofSet().add(document, {
      suite,
      purpose,
      documentLoader
    })
  } catch (e: any) {
    if (!documentLoader && e.name === 'jsonld.InvalidUrl') {
      const {
        details: { url }
      } = e
      const err = new Error(
        `A URL "${url as string}" could not be fetched; you need to pass ` +
          '"documentLoader" or resolve the URL before calling "sign".'
      )
      err.cause = e
      throw err
    }
    throw e
  }
}

/**
 * Verifies the linked data signature on the provided document.
 *
 * @param {object} document - The JSON-LD document with one or more proofs to be
 *   verified.
 *
 * @param {object} options - The options to use.
 * @param {LinkedDataSignature|LinkedDataSignature[]} options.suite -
 *   Acceptable signature suite instances for verifying the proof(s).
 *
 * @param {ProofPurpose} purpose - A proof purpose instance that will
 *   match proofs to be verified and ensure they were created according to
 *   the appropriate purpose.
 *
 * Advanced optional parameters and overrides:
 *
 * @param {function} [options.documentLoader]  - A custom document loader,
 *   `Promise<RemoteDocument> documentLoader(url)`.
 *
 * @return {Promise<{verified: boolean, results: Array,
 *   error: VerificationError}>}
 *   resolves with an object with a `verified` boolean property that is `true`
 *   if at least one proof matching the given purpose and suite verifies and
 *   `false` otherwise; a `results` property with an array of detailed results;
 *   if `false` an `error` property will be present, with `error.errors`
 *   containing all the errors that occurred during the verification process.
 */
export async function verify(
  document: object,
  {
    suite,
    purpose,
    documentLoader
  }: {
    suite: LinkedDataSignature
    purpose: ProofPurpose
    documentLoader: DocumentLoader
  }
): Promise<VerificationResult> {
  if (typeof document !== 'object') {
    throw new TypeError('The "document" parameter must be an object.')
  }
  const result = await new ProofSet().verify(document, {
    suite,
    purpose,
    documentLoader
  })
  const { error } = result
  if (error) {
    if (!documentLoader && error.name === 'jsonld.InvalidUrl') {
      const {
        details: { url }
      } = error
      const urlError = new Error(
        `A URL "${url as string}" could not be fetched; you need to pass ` +
          '"documentLoader" or resolve the URL before calling "verify".'
      )
      result.error = new VerificationError(urlError)
    } else {
      result.error = new VerificationError(error)
    }
  }
  return result
}
