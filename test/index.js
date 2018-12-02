const assert = require('assert')

const jwt = require('jsonwebtoken');
const JWT_TEST_SECRET = 'casbin-jwt-express-test-secret'

const casbinJWTExpress = require('../index')

describe('JWT Simple Sign', () => {
    
    it("should sign a JWT Token", () => {
        const tokenPayload = { 
            sub: "bob",
            policy: `p, bob, /dataset2/resource1, *
                p, bob, /dataset2/resource2, GET
                p, bob, /dataset2/folder1/*, POST`

        }
        var token = jwt.sign(tokenPayload, JWT_TEST_SECRET, {
            expiresIn: 10*60 // 10 mins
        });
        
        const decoded = jwt.decode(token)
        assert.equal(decoded.sub, tokenPayload.sub)
        assert.equal(decoded.policy, tokenPayload.policy)        
    })
})

describe("Tests a simple URL DENY and ALLOW access", () => {

    const modelSource = { fromText:  `
        [request_definition]
        r = sub, obj, act

        [policy_definition]
        p = sub, obj, act

        [policy_effect]
        e = some(where (p.eft == allow))

        [matchers]
        m = keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
        `
    }
    const tokenPayload = { 
        sub: "alice",
        policy: `
            p, alice, /dataset1/*, GET
            p, alice, /dataset1/resource1, POST
        `
    }
    var token = jwt.sign(tokenPayload, JWT_TEST_SECRET, {
        expiresIn: 10*60 // 10 mins
    });


    it("should enforce a policy and DENY access", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset2/forbidden",
            method: "GET",
            headers:{
                authorization:"Bearer " + token
            }
        }
        const res = {
            status: (code) => {
                return { 
                    send: () => {
                        assert.equal(code, 403)
                        done()
                    }
                }
            }
        }
        middlewareMock(req, res, () => done())

    })


    it("should enforce a policy and ALLOW access", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset2/resource1",
            method: "GET",
            headers:{
                authorization:"Bearer " + token
            }
        }
        const res = {
            status: () => {
                return { 
                    send: () => {
                        done()
                    }
                }
            }
        }
        middlewareMock(req, res, () => done())

    })

})