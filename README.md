# supabase

Unofficial [Supabase](https://supabase.io) auth-client for Go. A simple and dependency free API wrapper for handling authentication.

## Installation

```sh
go get github.com/intafuse/supabase
```

## Usage

Replace the `<SUPABASE-URL>` and `<SUPABASE-KEY>` placeholders with values from `https://supabase.com/dashboard/project/YOUR_PROJECT/settings/api`

### Sign-Up

```go
package main

import (
    "fmt"
    "context"
    "github.com/intafuse/supabase"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supa := supabase.CreateClient(supabaseUrl, supabaseKey)

  details, err := supa.SignUp(context.Background(), supabase.UserCredentials{
    Email:    "example@example.com",
    Password: "password",
    UsePKCE:  true,
  })
  if err != nil {
    panic(err)
  }

  fmt.Println(details)
}
```

### Sign-In

```go
package main

import (
    "fmt"
    "context"
    "github.com/intafuse/supabase"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supa := supabase.CreateClient(supabaseUrl, supabaseKey)

  user, err := supa.SignIn(context.Background(), supa.UserCredentials{
    Email:    "example@example.com",
    Password: "password",
  })
  if err != nil {
    panic(err)
  }

  fmt.Println(user)
}
```
