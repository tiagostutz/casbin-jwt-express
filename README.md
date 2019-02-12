# Casbin JWT Express

`casbin-jwt-express` is an authorization middleware that uses stateless JWT token to validate ACL rules using [Casbin](https://github.com/casbin/node-casbin)

To see it in action, clone this repo, go to **example** folder and run `npm install && npm start` (https://github.com/tiagostutz/casbin-jwt-express/tree/master/example)

It uses loaded policy rules applied to the enforced user directly from the JWT, so the authorization rules used in the enforcement process are not validated from a server or a file, but from the JWT token itself.

## Example

First install it:

`npm i --save casbin-jwt-express`

Then use it as a middleware:

```Javascript
    const jwtSecret = 'my-jwt-secret-used-to-sign-tokens'

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

  app.use(casbinJWTExpress(modelSource, jwtSecret, "/security/login"))
  
```

## JWT Spec

This middleware expects the underlying request to have an `Authorization` HTTP Header in format of `Bearer <JWT_TOKEN>`

The JWT token `payload` atteribute must having two attributes:
- `sub`:  the "user" (subject) of the rules to be applied. It must be your user identification on the systems. Can be an ID, a e-mail address, a login or whatever you use.
- `policy`: has the policies (ACL) that will be used to enforce the subject (user) authorization

## Middleware Initialization Parameters

- `modelSource`: Can be a filePath for a model file or a JSON Object with the String representation of the model. In case of the JSON model, it must have a `fromText` attribute with the text representation of the model. See below an example.
- `jwtSecret`: The secret used to sign the token so the middleware can decode the token and inspect its content. PS: Currently the middleware does not support certificate-based signature
- `ignoredPathsRegex`: if you want some URL patterns to not be enforced (like login URL), you can pass an String with a single Path or a Regex to match.
