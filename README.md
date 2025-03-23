# Nephelite

Nephelite is a WebAuthn based identity provider. It can be deployed into a kubernetes cluster using ArgoCD,
an example deployment is given below:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: nephelite
  namespace: argocd
spec:
  destination:
    namespace: nephelite
    server: https://kubernetes.default.svc
  project: default
  source:
    helm:
      values: |
        nephelite:
          host: identity.example.com
        ingress:
          enabled: true
          hosts:
            - host: identity.example.com
              paths:
                - path: /
                  pathType: Prefix
          tls:
            - secretName: example-tls-cert
              hosts:
                - identity.example.com
    repoURL: ghcr.io/norelect/charts
    chart: nephelite
    targetRevision: 0.2.4
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
```

## Adding users

Adding users is done via kubernetes custom resource. To get the custom resource definition for a specific
webauthn credential, you can generate it by visiting your `identity.example.com` page. It might look something like this:

```yaml
apiVersion: nephelite.norelect.ch/v1
kind: User
metadata:
  name: user
  namespace: nephelite
spec:
  credentials:
    - credentialId: pYvTYLGWqkJaD7LLLOswsg==
      publicKey: >-
        uSopNnYTUKtTR4F5wA0Y78N6akz3L22Zek5uNzl3+jDJ9fBQPYR7QEiGV+73OoHsPvs+37D8ANJ1MFthiw9aUw==
  email: user@example.com
  groups:
    - users
  username: user
```

## Integration with your apps

To integrate it with your OpenId connect compatible apps, create a new `Client` object like this:

```yaml
apiVersion: nephelite.norelect.ch/v1
kind: Client
metadata:
  name: app
  namespace: nephelite
spec:
  clientId: app
  clientSecret: secret
  confidential: true
  redirectUris:
    - https://app.example.com/auth/callback
```
