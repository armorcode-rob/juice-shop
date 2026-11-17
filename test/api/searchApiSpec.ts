/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
import type { Product as ProductConfig } from '../../lib/config.types'
import config from 'config'
const security = require('../../lib/insecurity')

const christmasProduct = config.get<ProductConfig[]>('products').filter(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge)[0]
const pastebinLeakProduct = config.get<ProductConfig[]>('products').filter(({ keywordsForPastebinDataLeakChallenge }) => keywordsForPastebinDataLeakChallenge)[0]

const API_URL = 'http://localhost:3000/api'
const REST_URL = 'http://localhost:3000/rest'

describe('/rest/products/search', () => {
  it('GET product search with no matches returns no products', () => {
    return frisby.get(`${REST_URL}/products/search?q=nomatcheswhatsoever`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with one match returns found product', () => {
    return frisby.get(`${REST_URL}/products/search?q=o-saft`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(1)
      })
  })

  it('GET product search with a stray quote and semicolon is treated as a literal search term', () => {
    return frisby.get(`${REST_URL}/products/search?q=';`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search UNION SELECT attack with two missing closing parenthesis is treated as a literal search term', () => {
    return frisby.get(`${REST_URL}/products/search?q=' union select id,email,password from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search UNION SELECT attack with one missing closing parenthesis is treated as a literal search term', () => {
    return frisby.get(`${REST_URL}/products/search?q=') union select id,email,password from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search SELECT * FROM attack is treated as a literal search term', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select * from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search cannot create UNION SELECT with Users table and fixed columns', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select '1','2','3','4','5','6','7','8','9' from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search cannot create UNION SELECT with Users table and required columns', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select id,'2','3',email,password,'6','7','8','9' from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
        expect(JSON.stringify(json)).not.toContain(`admin@${config.get<string>('application.domain')}`)
        expect(JSON.stringify(json)).not.toContain(security.hash('admin123'))
      })
  })

  it('GET product search cannot create UNION SELECT with sqlite_master table and required column', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
        expect(JSON.stringify(json)).not.toContain('CREATE TABLE')
      })
  })

  it('GET product search cannot select logically deleted christmas special by default', () => {
    return frisby.get(`${REST_URL}/products/search?q=seasonal%20special%20offer`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search by description cannot select logically deleted christmas special due to forced early where-clause termination', () => {
    return frisby.get(`${REST_URL}/products/search?q=seasonal%20special%20offer'))--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search cannot select logically deleted christmas special by trying to comment out the remainder of where clause', () => {
    return frisby.get(`${REST_URL}/products/search?q=${christmasProduct.name}'))--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search cannot select logically deleted unsafe product by trying to comment out the remainder of where clause', () => {
    return frisby.get(`${REST_URL}/products/search?q=${pastebinLeakProduct.name}'))--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with empty search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search?q=`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })

  it('GET product search without search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })
})
