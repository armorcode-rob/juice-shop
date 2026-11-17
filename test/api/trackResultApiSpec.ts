/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
const Joi = frisby.Joi

const REST_URL = 'http://localhost:3000/rest'

describe('/rest/track-order/:id', () => {
  it('GET tracking results for the order id', () => {
    return frisby.get(REST_URL + '/track-order/5267-f9cd5882f54c75a3')
      .expect('status', 200)
      .expect('json', {})
  })

  it('GET injecting into orderId does not return other orders', () => {
    return frisby.get(REST_URL + '/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', 'data.*', {
        orderId: Joi.string()
      })
      .then(({ json }) => {
        expect(json.data.length).toBe(1)
        expect(json.data[0].email).toBeUndefined()
        expect(json.data[0].products).toBeUndefined()
      })
  })
})
