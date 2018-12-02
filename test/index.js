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

    it("should enforce a simple policy", (done) => {
        const modelSource = { fromText:  `[request_definition]
            r = sub, obj, act
            
            [policy_definition]
            p = sub, obj, act
            
            [policy_effect]
            e = some(where (p.eft == allow))
            
            [matchers]
            m = keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
            `
        }

        const middlewareMock = casbinJWTExpress(modelSource, JWT_TEST_SECRET, "/security/login")
        const tokenPayload = { 
            sub: "bob",
            policy: "p, alice, /dataset1/*, GET\np, alice, /dataset1/resource1, POST\np, bob, /dataset2/resource1, *\np, bob, /dataset2/resource2, GET\np, bob, /dataset2/folder1/*, POST\np, dataset1_admin, /dataset1/*, *\ng, cathy, dataset1_admin"
        }
        var token = jwt.sign(tokenPayload, JWT_TEST_SECRET, {
            expiresIn: 10*60 // 10 mins
        });

        const req = { 
            originalUrl: {
                match: function(str) {
                    return this.path.match(str)
                },
                path: "/dataset2/resource1"
            },
            method: "GET",
            headers:{
                authorization:"Bearer " + token
            }
        }
        const res = {
            status: () => {
                return { 
                    send: () => {}
                }
            }
        }
        middlewareMock(req, res, () =>{
            console.log('END!');
            done()            
        })
    })
})