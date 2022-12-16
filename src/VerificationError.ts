/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
/**
 * Used as an umbrella wrapper around multiple verification errors.
 */
export class VerificationError extends Error {
  errors: Error[]

  /**
   * @param {Error|Error[]} errors
   */
  constructor(errors: Error | Error[]) {
    super('Verification error(s).')

    this.name = 'VerificationError'
    this.errors = Array.isArray(errors) ? errors : [errors]
    // Because we are extending a built-in class
    Object.setPrototypeOf(this, VerificationError.prototype)
  }
}
