/*!
 * Copyright (c) 2022 Digital Credentials Consortium. (Conversion to Typescript)
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
import { ControllerProofPurpose } from './ControllerProofPurpose'
import { Controller, DateType } from '../types'

export class AssertionProofPurpose extends ControllerProofPurpose {
  constructor({
    term = 'assertionMethod',
    controller,
    date,
    maxTimestampDelta = Infinity
  }: {
    term?: string
    controller: Controller
    date?: DateType
    maxTimestampDelta?: number
  }) {
    super({ term, controller, date, maxTimestampDelta })
  }
}
