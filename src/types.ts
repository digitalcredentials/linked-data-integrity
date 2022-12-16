/*!
 * Copyright (c) 2022 Digital Credentials Consortium.
 */
export type DateType = Date | string | number

export type URI = string

export interface ControllerObject {
  id: string
  [x: string]: any
}

export type Controller = URI | ControllerObject

export interface DocumentLoaderResult {
  contextUrl?: string
  documentUrl?: string
  document: any
}

export type DocumentLoader = (url: string) => Promise<DocumentLoaderResult>

export interface Proof {
  type: string
  challenge?: string
  domain?: string
  [x: string]: any
}

export interface Signer {
  id: string
  algorithm?: string
  sign: ({ data }: { data: Uint8Array }) => Promise<Uint8Array>
}

export interface Verifier {
  id: string
  verify: ({
    data,
    signature
  }: {
    data: Uint8Array
    signature: Uint8Array
  }) => Promise<boolean>
}

export interface SignatureCryptoParams {
  verificationMethod: VerificationMethod
  key?: any
  signer?: Signer
  verifier?: Verifier
}

export interface ValidationResult {
  valid: boolean
  controller?: Controller
  error?: Error
}

export interface VerificationMethodObject {
  id: string
  controller: Controller
  [x: string]: any
}

export type VerificationMethod = URI | VerificationMethodObject

export interface VerificationResult {
  verified: boolean
  verificationMethod?: VerificationMethod
  results?: any[]
  error?: Error | any
}
