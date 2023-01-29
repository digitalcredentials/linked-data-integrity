/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2017-2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as jsonld from 'jsonld'
import { sha256digest } from '@digitalcredentials/sha256-universal'
import { constants } from '../constants'
import { LinkedDataProofSuite } from './LinkedDataProofSuite'
import {
  DateType,
  DocumentLoader,
  Proof,
  SignatureCryptoParams,
  Signer,
  VerificationMethod,
  VerificationResult,
  Verifier
} from '../types'
import { concat, w3cDate } from '../util'
import { ProofPurpose } from '../purposes'

export abstract class LinkedDataSignature extends LinkedDataProofSuite {
  KeyPairClass: any
  contextUrl: string
  proof?: Proof
  verificationMethod?: VerificationMethod
  key?: any
  signer?: Signer
  verifier?: Verifier
  useNativeCanonize?: boolean
  date?: Date
  private _hashCache: any
  /**
   * Parent class from which the various LinkDataSignature suites (such as
   * `Ed25519Signature2020`) inherit.
   * NOTE: Developers are never expected to use this class directly, but to
   * only work with individual suites.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.type - Suite name, provided by subclass.
   * @param {KeyPairClass} KeyPairClass - The keypair key class that this suite
   *   will use to sign/verify signatures. Provided by subclass. Used
   *   during the `verifySignature` operation, to create an instance (containing
   *   a `verifier()` property) of a public key fetched via a `documentLoader`.
   *
   * @param {string} contextUrl - JSON-LD context URL that corresponds to this
   *   signature suite. Provided by subclass. Used for enforcing suite context
   *   during the `sign()` operation.
   *
   * For `sign()` operations, either a `key` OR a `signer` is required.
   * For `verify()` operations, you can pass in a verifier (from KMS), or
   * the public key will be fetched via documentLoader.
   *
   * @param {object} [options.key] - An optional key object (containing an
   *   `id` property, and either `signer` or `verifier`, depending on the
   *   intended operation. Useful for when the application is managing keys
   *   itself (when using a KMS, you never have access to the private key,
   *   and so should use the `signer` param instead).
   *
   * @param {{sign: Function, id: string}} [options.signer] - Signer object
   *   that has two properties: an async `sign()` method, and an `id`. This is
   *   useful when interfacing with a KMS (since you don't get access to the
   *   private key and its `signer`, the KMS client gives you only the signer
   *   object to use).
   *
   * @param {{verify: Function, id: string}} [options.verifier] - Verifier
   *   object that has two properties: an async `verify()` method, and an `id`.
   *   Useful when working with a KMS-provided verifier.
   *
   * Advanced optional parameters and overrides:
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2). If not provided, this is
   *   constructed during signing.
   * @param {string|Date} [options.date] - Signing date to use (otherwise
   *   defaults to `now()`).
   * @param {boolean} [options.useNativeCanonize] - Whether to use a native
   *   canonize algorithm.
   */
  constructor({
    type,
    proof,
    KeyPairClass,
    date,
    key,
    signer,
    verifier,
    useNativeCanonize = false,
    contextUrl
  }: {
    type: string
    proof?: Proof
    KeyPairClass: any
    date?: DateType
    key?: any
    signer?: Signer
    verifier?: Verifier
    useNativeCanonize?: boolean
    contextUrl: string
  }) {
    super({ type })
    this.KeyPairClass = KeyPairClass
    this.contextUrl = contextUrl
    this.proof = proof
    const vm = _processSignatureParams({
      key,
      signer,
      verifier
    } as SignatureCryptoParams)
    this.verificationMethod = vm.verificationMethod
    this.key = vm.key
    this.signer = vm.signer
    this.verifier = vm.verifier
    if (date) {
      this.date = new Date(date)
    }
    this.useNativeCanonize = useNativeCanonize
    this._hashCache = null
  }

  /**
   * @param document {object} to be signed.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  async createProof({
    document,
    purpose,
    documentLoader
  }: {
    document: any
    purpose: ProofPurpose
    documentLoader: DocumentLoader
  }): Promise<Proof> {
    // build proof (currently known as `signature options` in spec)
    let proof: Proof
    if (this.proof) {
      // shallow copy
      proof = { ...this.proof }
    } else {
      // create proof JSON-LD document
      proof = { type: '' }
    }

    // ensure proof type is set
    proof.type = this.type

    // set default `now` date if not given in `proof` or `options`
    let date: DateType | undefined = this.date
    if (proof.created === undefined && date === undefined) {
      date = new Date()
    }

    // ensure date is in string format
    if (date) {
      date = w3cDate(date)
    }

    // add API overrides
    if (date) {
      proof.created = date
    }

    proof.verificationMethod = this.verificationMethod

    // add any extensions to proof (mostly for legacy support)
    proof = await this.updateProof({
      document,
      proof,
      purpose,
      documentLoader
    })

    // allow purpose to update the proof; the `proof` is in the
    // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
    // ensure any added fields are also represented in that same `@context`
    proof = await purpose.update(proof, {
      document,
      suite: this,
      documentLoader
    })

    // create data to sign
    const verifyData = await this.createVerifyData({
      document,
      proof,
      documentLoader
    })

    // sign data
    proof = await this.sign({
      verifyData,
      proof
    })

    return proof
  }

  /**
   * @param document {object} to be signed.
   * @param proof {Proof}
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */

  async updateProof({
    document,
    proof,
    purpose,
    documentLoader
  }: {
    document: any
    proof: Proof
    purpose: ProofPurpose
    documentLoader: DocumentLoader
  }): Promise<Proof> {
    // extending classes may do more
    return proof
  }

  /**
   * @param proof {object} the proof to be verified.
   * @param document {object} the document the proof applies to.
   * @param documentLoader {function}
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({
    document,
    proof,
    documentLoader
  }: {
    document: any
    proof: Proof
    documentLoader: DocumentLoader
  }): Promise<VerificationResult> {
    try {
      // create data to verify
      const verifyData = await this.createVerifyData({
        document,
        proof,
        documentLoader
      })

      // fetch verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        documentLoader
      })

      // verify signature on data
      const verified = await this.verifySignature({
        verifyData,
        verificationMethod,
        proof
      })
      if (!verified) {
        throw new Error('Invalid signature.')
      }

      return { verified: true, verificationMethod }
    } catch (error: any) {
      return { verified: false, error }
    }
  }

  async canonize(
    input: any,
    {
      documentLoader,
      skipExpansion
    }: {
      documentLoader: DocumentLoader
      skipExpansion?: boolean
    }
  ): Promise<any> {
    return jsonld.canonize(input, {
      algorithm: 'URDNA2015',
      // do not resolve any relative URLs or terms, throw errors instead
      base: null,
      format: 'application/n-quads',
      documentLoader,
      // throw errors if any values would be dropped due to missing
      // definitions or relative URLs
      safe: true,
      skipExpansion,
      useNative: this.useNativeCanonize
    })
  }

  async canonizeProof(
    proof: Proof,
    {
      document,
      documentLoader
    }: {
      document: any
      documentLoader: DocumentLoader
    }
  ): Promise<any> {
    // `jws`,`signatureValue`,`proofValue` must not be included in the proof
    // options
    proof = {
      '@context': document['@context'] || constants.SECURITY_CONTEXT_URL,
      ...proof
    }
    delete proof.jws
    delete proof.signatureValue
    delete proof.proofValue
    return this.canonize(proof, {
      documentLoader,
      skipExpansion: false
    })
  }

  /**
   * @param document {object} to be signed/verified.
   * @param proof {object}
   * @param documentLoader {function}
   *
   * @returns {Promise<{Uint8Array}>}.
   */
  async createVerifyData({
    document,
    proof,
    documentLoader
  }: {
    document: any
    proof: Proof
    documentLoader: DocumentLoader
  }): Promise<Uint8Array> {
    // get cached document hash
    let cachedDocHash
    const { _hashCache } = this
    if (_hashCache && _hashCache.document === document) {
      cachedDocHash = _hashCache.hash
    } else {
      this._hashCache = {
        document,
        // canonize and hash document
        hash: (cachedDocHash = this.canonize(document, {
          documentLoader
        }).then(async (c14nDocument) => sha256digest(c14nDocument)))
      }
    }

    // await both c14n proof hash and c14n document hash
    const [proofHash, docHash] = await Promise.all([
      // canonize and hash proof
      this.canonizeProof(proof, {
        document,
        documentLoader
      }).then(async (c14nProofOptions) => sha256digest(c14nProofOptions)),
      cachedDocHash
    ])

    // concatenate hash of c14n proof options and hash of c14n document
    return concat(proofHash, docHash)
  }

  /**
   * @param proof {object}
   * @param documentLoader {function}
   */
  async getVerificationMethod({
    proof,
    documentLoader
  }: {
    proof: Proof
    documentLoader: DocumentLoader
  }): Promise<VerificationMethod> {
    let { verificationMethod } = proof

    if (typeof verificationMethod === 'object') {
      verificationMethod = verificationMethod.id
    }

    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.')
    }

    const framedVerificationMethod = await jsonld.frame(
      verificationMethod,
      {
        '@context': constants.SECURITY_CONTEXT_URL,
        '@embed': '@always',
        id: verificationMethod
      },
      { documentLoader, compactToRelative: false }
    )
    if (!framedVerificationMethod) {
      throw new Error(
        `Verification method ${verificationMethod as string} not found.`
      )
    }

    // ensure verification method has not been revoked
    if (framedVerificationMethod.revoked !== undefined) {
      throw new Error('The verification method has been revoked.')
    }

    return framedVerificationMethod
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param document {object} to be signed.
   * @param proof {object}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  abstract sign({
    verifyData,
    proof
  }: {
    verifyData: Uint8Array
    proof: Proof
  }): Promise<Proof>

  /**
   * @param verifyData {Uint8Array}.
   * @param verificationMethod {object}.
   * @param document {object} to be signed.
   * @param proof {object}
   *
   * @returns {Promise<boolean>}
   */
  abstract verifySignature({
    verifyData,
    verificationMethod,
    proof
  }: {
    verifyData: Uint8Array
    verificationMethod: VerificationMethod
    proof: Proof
  }): Promise<boolean>

  /**
   * Ensures the document to be signed contains the required signature suite
   * specific `@context`, by either adding it (if `addSuiteContext` is true),
   * or throwing an error if it's missing.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.document - JSON-LD document to be signed.
   * @param {boolean} options.addSuiteContext - Add suite context?
   */
  ensureSuiteContext({
    document,
    addSuiteContext
  }: {
    document: any
    addSuiteContext: boolean
  }): void {
    const { contextUrl } = this

    if (_includesContext({ document, contextUrl })) {
      // document already includes the required context
      return
    }

    if (!addSuiteContext) {
      throw new TypeError(
        `The document to be signed must contain this suite's @context, ` +
          `"${contextUrl}".`
      )
    }

    // enforce the suite's context by adding it to the document
    const existingContext = document['@context'] || []

    document['@context'] = Array.isArray(existingContext)
      ? [...existingContext, contextUrl]
      : [existingContext, contextUrl]
  }
}

/**
 * Tests whether a provided JSON-LD document includes a context URL in its
 * `@context` property.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.document - A JSON-LD document.
 * @param {string} options.contextUrl - A context URL.
 *
 * @returns {boolean} Returns true if document includes context.
 */
function _includesContext({
  document,
  contextUrl
}: {
  document: any
  contextUrl: string
}): boolean {
  const context = document['@context']
  return (
    context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl))
  )
}

/**
 * See constructor docstring for param details.
 *
 * @returns {{verificationMethod: string, key: KeyPairClass,
 *   signer: {sign: Function, id: string},
 *   verifier: {verify: Function, id: string}}} - Validated and initialized
 *   key-related parameters.
 */
function _processSignatureParams({
  key,
  signer,
  verifier
}: SignatureCryptoParams): SignatureCryptoParams {
  // We are explicitly not requiring a key or signer/verifier param to be
  // present, to support the verify() use case where the verificationMethod
  // is being fetched by the documentLoader

  const vm: SignatureCryptoParams = { verificationMethod: '' }
  if (key) {
    vm.key = key
    vm.verificationMethod = key.id
    if (typeof key.signer === 'function') {
      vm.signer = key.signer()
    }
    if (typeof key.verifier === 'function') {
      vm.verifier = key.verifier()
    }
    if (!(vm.signer ?? vm.verifier)) {
      throw new TypeError(
        'The "key" parameter must contain a "signer" or "verifier" method.'
      )
    }
  } else {
    if (!(vm.signer?.id ?? vm.verifier?.id)) {
      throw new TypeError(
        'The "key" parameter must contain a "signer" or "verifier" object.'
      )
    }
    // @ts-ignore
    vm.verificationMethod = signer?.id ?? verifier?.id
    vm.signer = signer
    vm.verifier = verifier
  }

  if (vm.signer) {
    if (typeof vm.signer.sign !== 'function') {
      throw new TypeError('A signer API has not been specified.')
    }
  }
  if (vm.verifier) {
    if (typeof vm.verifier.verify !== 'function') {
      throw new TypeError('A verifier API has not been specified.')
    }
  }

  return vm
}
