# Casbin JWT Express

casbin-jwt-express is an authorization middleware that uses stateless JWT token for Express.js based on Casbin

It uses loaded policy rules applied to the enforced user directly from the JWT, so the authorization rules used in the enforcement process are not validated from a server or a file, but from the JWT token itself.

## Example

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

- The JWT token `payload` must have two attributes:
    - `sub`:  the "user" (subject) of the rules to be applied. It must be your user identification on the systems. Can be an ID, a e-mail address, a login or whatever you use.
    - `policy`: has the applied policies to the user having the permissions enforced.
- The provided `jwtSecret` provided in the initialization of this middleware must be the same as the one used to sign the JWT Token.

## Middleware Parameters

- `modelSource`: Can be a filePath for a model file or a JSON Object with the String representation of the model. In case of the JSON model, it must have a `fromText` attribute with the text representation of the model. See below an example.
- `jwtSecret`: The secret used to sign the token. PS: Currently the middleware does not support certificate-based signature
- `ignoredPathsRegex`: if you want some URL patterns to not be enforced (like login URL), you can pass an String with a single Path or a Regex to match.