
/* for making HTTP request in testing */
const request = require('supertest')

const app = require('./app')

const redisClient = require('./redis/redisClient')
const db = require('./db/dbConfig')

/* unit test for general app routes */
describe('App Routes (using mocked Redis)', () => {
    test('GET / should return welcome message', async () => {
        const response = await request(app).get('/')
        expect(response.statusCode).toBe(200)
        expect(response.text).toBe('Welcome to Red Canary Take Home Test.')
    })

    test('GET /unknown should return 404 for non-existing routes', async () => {
        const response = await request(app).get('/unknown')
        expect(response.statusCode).toBe(404)
        expect(response.body).toEqual({ success: false, data: { error: 'Page not found.' } })
    })
})

/* close Redis and PostgreSQL connections after all tests are finished */
afterAll(async () => {
    if (redisClient.quit) {
        await redisClient.quit()
    }

    if (db && db.$pool && db.$pool.end) {
        await db.$pool.end()
    }
})