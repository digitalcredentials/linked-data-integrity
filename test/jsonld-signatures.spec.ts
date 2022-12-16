import { expect } from 'chai'
import {
  AssertionProofPurpose,
  constants,
  DataIntegrityProof,
  Proof
} from '../src'

declare module 'jsonld'
declare module '@digitalbazaar/security-context'
declare module 'serialize-error'

describe('jsonld-signatures', () => {
  it('exports constants', async () => {
    expect(constants.SECURITY_PROOF_URL).to.equal('https://w3id.org/security#proof')
  })

  it('exports AssertionProofPurpose', async () => {
    const proof: Proof = { proofPurpose: 'assertionMethod', type: 'TestProof' }
    const purpose = new AssertionProofPurpose({ controller: 'https://example.com' })
    expect(await purpose.match(proof)).to.equal(true)
  })

  it('exports DataIntegrityProof', async () => {
    expect(DataIntegrityProof).to.exist
  })
})
