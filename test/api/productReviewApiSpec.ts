/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { type IncomingMessage } from 'http'
const Joi = frisby.Joi
const security = require('../../lib/insecurity')
const http = require('http')

const REST_URL = 'http://localhost:3000/rest'

const jsonHeader = { 'content-type': 'application/json' }
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

describe('/rest/products/:id/reviews', () => {
  const reviewResponseSchema = {
    id: Joi.number(),
    product: Joi.number(),
    message: Joi.string(),
    author: Joi.string()
  }

  it('GET product reviews by product id', () => {
    return frisby.get(`${REST_URL}/products/1/reviews`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', reviewResponseSchema)
  })

  it('GET product reviews rejects an injected mongoDB sleep command as product id', () => {
    return frisby.get(`${REST_URL}/products/sleep(1)/reviews`)
      .expect('status', 400)
  })

  it('GET product reviews by alphanumeric non-mongoDB-command product id', () => {
    return frisby.get(`${REST_URL}/products/kaboom/reviews`)
      .expect('status', 400)
  })

  it('PUT single product review can be created', () => {
    return frisby.put(`${REST_URL}/products/1/reviews`, {
      body: {
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      }
    })
      .expect('status', 201)
      .expect('header', 'content-type', /application\/json/)
  })
})

describe('/rest/products/reviews', () => {
  const updatedReviewResponseSchema = {
    modified: Joi.number(),
    original: Joi.array(),
    updated: Joi.array()
  }

  let reviewId: string

  beforeAll((done) => {
    http.get(`${REST_URL}/products/1/reviews`, (res: IncomingMessage) => {
      let body = ''

      res.on('data', (chunk: string) => {
        body += chunk
      })

      res.on('end', () => {
        const response = JSON.parse(body)
        reviewId = response.data[0]._id
        done()
      })
    })
  })

  it('PATCH single product review can be edited', () => {
    return frisby.patch(`${REST_URL}/products/reviews`, {
      headers: authHeader,
      body: {
        id: reviewId,
        message: 'Lorem Ipsum'
      }
    })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', updatedReviewResponseSchema)
  })

  it('PATCH single product review editing need an authenticated user', () => {
    return frisby.patch(`${REST_URL}/products/reviews`, {
      body: {
        id: reviewId,
        message: 'Lorem Ipsum'
      }
    })
      .expect('status', 401)
  })

  it('POST non-existing product review cannot be liked', () => {
    return frisby.post(`${REST_URL}/user/login`, {
      headers: jsonHeader,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      }
    })
      .expect('status', 200)
      .then(({ json: jsonLogin }) => {
        return frisby.post(`${REST_URL}/products/reviews`, {
          headers: { Authorization: `Bearer ${jsonLogin.authentication.token}` },
          body: {
            id: 'does not exist'
          }
        })
          .expect('status', 404)
      })
  })

  it('POST single product review can be liked', () => {
    return frisby.post(`${REST_URL}/user/login`, {
      headers: jsonHeader,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      }
    })
      .expect('status', 200)
      .then(({ json: jsonLogin }) => {
        return frisby.post(`${REST_URL}/products/reviews`, {
          headers: { Authorization: `Bearer ${jsonLogin.authentication.token}` },
          body: {
            id: reviewId
          }
        })
          .expect('status', 200)
          .expect('jsonTypes', { likesCount: Joi.number() })
      })
  })

  it('PATCH multiple product reviews via query operator injection is rejected', () => {
    return frisby.patch(`${REST_URL}/products/reviews`, {
      headers: authHeader,
      body: {
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      }
    })
      .expect('status', 400)
  })

  it('POST liking a product review via query operator injection is rejected', () => {
    return frisby.post(`${REST_URL}/user/login`, {
      headers: jsonHeader,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      }
    })
      .expect('status', 200)
      .then(({ json: jsonLogin }) => {
        return frisby.post(`${REST_URL}/products/reviews`, {
          headers: { Authorization: `Bearer ${jsonLogin.authentication.token}` },
          body: {
            id: { $ne: -1 }
          }
        })
          .expect('status', 400)
      })
  })
})
