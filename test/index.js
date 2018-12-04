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


describe("Bad Request", () => {

    const modelSource = { fromText:  `
        [request_definition]
        r = sub, obj, act
        
        [policy_definition]
        p = sub, obj, act
        
        [policy_effect]
        e = some(where (p.eft == allow))
        
        [matchers]
        m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
    `
    }

    it("Tests a simple request DENY for lacking the Authorization HTTP Header on the request", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset1/allowedButNot",
            method: "GET",
            headers:{
                none: "No header"
            }
        }
        const res = {
            status: (code) => {
                return { 
                    send: () => {
                        assert.equal(code, 400)
                        done()
                    }
                }
            }
        }
        middlewareMock(req, res, () => done())

    })
})
describe("Tests a simple URL DENY and ALLOW access for the same user (subject)", () => {

    const modelSource = { fromText:  `
        [request_definition]
        r = sub, obj, act
        
        [policy_definition]
        p = sub, obj, act
        
        [policy_effect]
        e = some(where (p.eft == allow))
        
        [matchers]
        m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
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


    it("should enforce a policy and DENY access by URL forbidden", (done) => {

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

    it("should enforce a policy and DENY access by URL forbidden", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset2/resource1",
            method: "POST",
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

    it("should enforce a policy and ALLOW access by URL * and Method GET", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset1/any",
            method: "GET",
            headers:{
                authorization:"Bearer " + token
            }
        }
        const res = {
            status: (code) => {
                return { 
                    send: () => {
                        assert.equal(code, 200)
                        done()
                    }
                }
            }
        }
        middlewareMock(req, res, () => done())

    })    

    it("should enforce a policy and DENY access by HTTP Method", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset1/any",
            method: "POST",
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


    it("should enforce a policy and ALLOW access by HTTP Method", (done) => {

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const req = { 
            originalUrl:  "/dataset1/resource1",
            method: "POST",
            headers:{
                authorization:"Bearer " + token
            }
        }
        const res = {
            status: (code) => {
                return { 
                    send: () => {
                        assert.equal(code, 200)
                        done()
                    }
                }
            }
        }
        middlewareMock(req, res, () => done())
    })        
})

