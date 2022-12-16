/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import { base58btc } from '../baseX'
import { LinkedDataProofSuite } from './LinkedDataProofSuite'
import {
  DateType,
  DocumentLoader,
  Proof,
  SignatureCryptoParams,
  Signer,
  VerificationMethod,
  VerificationResult
} from '../types'
import { concat, w3cDate } from '../util'
import { sha256digest } from '@digitalcredentials/sha256-universal'
import { ProofPurpose } from '../purposes'

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z'
const DATA_INTEGRITY_CONTEXT = 'https://w3id.org/security/data-integrity/v1'
const PROOF_TYPE = 'DataIntegrityProof'

export class DataIntegrityProof extends LinkedDataProofSuite {
  contextUrl: string
  createVerifier: any
  canonize: any
  cryptosuite: any
  date: Date
  requiredAlgorithm: any
  signer?: Signer
  verificationMethod: VerificationMethod
  _hashCache?: { document: any; hash: any }
  proof?: Proof

  constructor({
    signer,
    date = new Date(),
    cryptosuite
  }: {
    signer: Signer
    date: DateType
    cryptosuite: any
  }) {
    super({ type: PROOF_TYPE })
    const { canonize, createVerifier, name, requiredAlgorithm } = cryptosuite
    if (!(createVerifier && typeof createVerifier === 'function')) {
      throw new Error('"cryptosuite" must provide a "createVerifier" function.')
    }

    this.contextUrl = DATA_INTEGRITY_CONTEXT
    this.canonize = canonize
    this.createVerifier = createVerifier
    this.cryptosuite = name
    this.requiredAlgorithm = requiredAlgorithm
    this.date = new Date(date)

    const vm = _processSignatureParams({ signer, requiredAlgorithm })
    this.verificationMethod = vm.verificationMethod
    this.signer = vm.signer
  }

  /**
   * Adds a signature (proofValue) field to the proof object. Called by
   * LinkedDataSignature.createProof().
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Data to be signed (extracted
   *   from document, according to the suite's spec).
   * @param {object} options.proof - Proof object (containing the proofPurpose,
   *   verificationMethod, etc).
   *
   * @returns {Promise<object>} Resolves with the proof containing the signature
   *   value.
   */
  async sign({
    verifyData,
    proof
  }: {
    verifyData: Uint8Array
    proof: Proof
  }): Promise<Proof> {
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.')
    }

    const signatureBytes = await this.signer.sign({ data: verifyData })
    proof.proofValue = `${MULTIBASE_BASE58BTC_HEADER}${base58btc.encode(
      signatureBytes
    )}`

    return proof
  }

  /**
   * Verifies the proof signature against the given data.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Canonicalized hashed data.
   * @param {object} options.verificationMethod - Key object.
   * @param {object} options.proof - The proof to be verified.
   *
   * @returns {Promise<boolean>} Resolves with the verification result.
   */
  async verifySignature({
    verifyData,
    verificationMethod,
    proof
  }: {
    verifyData: Uint8Array
    verificationMethod: VerificationMethod
    proof: Proof
  }): Promise<boolean> {
    const verifier = await this.createVerifier({ verificationMethod })
    if (this.requiredAlgorithm !== verifier.algorithm) {
      const message =
        `The verifier's algorithm ` +
        `"${verifier.algorithm as string}" ` +
        `does not match the required algorithm for the cryptosuite ` +
        `"${this.requiredAlgorithm as string}".`
      throw new Error(message)
    }

    const { proofValue } = proof
    if (!(proofValue && typeof proofValue === 'string')) {
      throw new TypeError(
        'The proof does not include a valid "proofValue" property.'
      )
    }
    if (proofValue[0] !== MULTIBASE_BASE58BTC_HEADER) {
      throw new Error('Only base58btc multibase encoding is supported.')
    }
    const signatureBytes = base58btc.decode(proofValue.substr(1))

    return verifier.verify({ data: verifyData, signature: signatureBytes })
  }

  /**
   * @param document.document
   * @param document - {object} To be signed.
   * @param purpose - {ProofPurpose}.
   * @param documentLoader - {function}.
   *
   * @param document.purpose
   * @param document.documentLoader
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
      proof = {} as Proof
    }

    // ensure proof type is set
    proof.type = this.type

    // set default `now` date if not given in `proof`
    if (!proof.created) {
      proof.created = w3cDate(this.date)
    }

    proof.verificationMethod = this.verificationMethod
    proof.cryptosuite = this.cryptosuite

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
    proof = await this.sign({ verifyData, proof })

    return proof
  }

  /**
   * @param proof.proof
   * @param proof - {object} The proof to be verified.
   * @param document - {object} The document the proof applies to.
   * @param documentLoader - {function}.
   *
   * @param proof.document
   * @param proof.documentLoader
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({
    proof,
    document,
    documentLoader
  }: {
    proof: Proof
    document: any
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

  /**
   * @param document.document
   * @param document - {object} To be signed/verified.
   * @param proof - {object}.
   * @param documentLoader - {function}.

   *
   * @param document.proof
   * @param document.documentLoader
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
        hash: (cachedDocHash = this.canonize(document, { documentLoader }).then(
          async (c14nDocument: any) => sha256digest(c14nDocument)
        ))
      }
    }

    // await both c14n proof hash and c14n document hash
    const [proofHash, docHash] = await Promise.all([
      // canonize and hash proof
      this.canonizeProof(proof, { document, documentLoader }).then(
        async (c14nProofOptions) => sha256digest(c14nProofOptions)
      ),
      cachedDocHash
    ])
    // concatenate hash of c14n proof options and hash of c14n document
    return concat(proofHash, docHash)
  }

  /**
   * @param document - {object} To be signed.
   * @param document.proof
   * @param proof - {object}.
   * @param documentLoader - {function}.
   * @param document.documentLoader
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

    const result = await documentLoader(verificationMethod)
    if (!result) {
      throw new Error(
        `Unable to load verification method "${verificationMethod as string}".`
      )
    }

    const { document } = result
    verificationMethod =
      typeof document === 'string' ? JSON.parse(document) : document
    return verificationMethod
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
    // `proofValue` must not be included in the proof options
    proof = {
      '@context': DATA_INTEGRITY_CONTEXT,
      ...proof
    }
    delete proof.proofValue
    return this.canonize(proof, { documentLoader, skipExpansion: false })
  }

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
    addSuiteContext?: boolean
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
 * @param options
 * @param options.signer
 * @param options.requiredAlgorithm
 * @returns {{verificationMethod: string
 *   signer: {sign: Function, id: string, algorithm: String}}}} - Validated and
 *   initialized signature-related parameters.
 */
function _processSignatureParams({
  signer,
  requiredAlgorithm
}: {
  signer: Signer
  requiredAlgorithm: string
}): SignatureCryptoParams {
  const vm: SignatureCryptoParams = {
    verificationMethod: '',
    signer: undefined
  }

  if (!signer) {
    return vm
  }

  if (typeof signer.sign !== 'function') {
    throw new TypeError('A signer API has not been specified.')
  }
  if (requiredAlgorithm !== signer.algorithm) {
    const message =
      `The signer's algorithm ` +
      `"${signer.algorithm as string}" ` +
      `does not match the required algorithm for the cryptosuite ` +
      `"${requiredAlgorithm}".`
    throw new Error(message)
  }

  vm.signer = signer
  vm.verificationMethod = signer.id

  return vm
}
