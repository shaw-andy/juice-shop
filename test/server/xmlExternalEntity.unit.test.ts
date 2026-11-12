/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseXmlString } from '../../lib/xml'

const CANARY = 'XXE_CANARY_NOT_A_SECRET'

async function parsedText (xml: string): Promise<string> {
  try {
    return await parseXmlString(xml)
  } catch (err: unknown) {
    return err instanceof Error ? err.message : String(err)
  }
}

void describe('parseXmlString external entities', () => {
  let dir = ''
  let secretPath = ''
  let fileUrl = ''
  let dtdUrl = ''

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-xxe-'))
    secretPath = path.join(dir, 'local.txt')
    fs.writeFileSync(secretPath, CANARY)
    fileUrl = pathToFileURL(secretPath).href
    const dtdPath = path.join(dir, 'ext.dtd')
    fs.writeFileSync(dtdPath, `<!ENTITY xxe SYSTEM "${fileUrl}">`)
    dtdUrl = pathToFileURL(dtdPath).href
  })

  after(() => {
    if (dir !== '') {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  void it('does not return a local file referenced by a file URL general entity', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${fileUrl}">]><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })

  void it('does not return a local file referenced by an uppercase file URL', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${fileUrl.replace('file:', 'FILE:')}">]><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })

  void it('does not return a local file referenced by a localhost file URL', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://localhost${secretPath}">]><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })

  void it('does not return a local file referenced by an absolute filesystem path', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${secretPath}">]><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })

  void it('does not return a local file pulled in by an external DTD', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo SYSTEM "${dtdUrl}"><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })

  void it('does not return a local file pulled in by an external parameter entity', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % ext SYSTEM "${dtdUrl}">%ext;]><foo>&xxe;</foo>`
    assert.equal((await parsedText(xml)).includes(CANARY), false)
  })
})
