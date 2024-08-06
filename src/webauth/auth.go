package webauth

import (
	"encoding/json"
	"fmt"
	"gokart/src/datastore"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

type Login struct {
	Username string
}

// Your initialization function
func Init() *http.ServeMux {
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",                               // Display Name for your site
		RPID:          "go-webauthn.local",                         // Generally the FQDN for your site
		RPOrigins:     []string{"https://login.go-webauthn.local"}, // The origin URLs allowed for WebAuthn requests
	}

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}
	authRouter := http.NewServeMux()
	authRouter.HandleFunc("/BeginRegistration", BeginRegistration)
	authRouter.HandleFunc("/FinishRegistration", FinishRegistration)
	authRouter.HandleFunc("/BeginLogin", BeginLogin)
	authRouter.HandleFunc("/FinishLogin", FinishLogin)

	return authRouter
}

// ======================
// Registering an account
// ======================
//

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	l, err := getUserFromBody(r, w)
	if err != nil {
		return
	}
	user := datastore.GetUser(l.Username) // Find or create the new user
	options, session, err := webAuthn.BeginRegistration(user)
	// handle errors if present
	// store the sessionData values
	if err != nil {
		http.Error(w, "Webauth reg failed", 500)
		return
	}

	user.SaveSession(session)

	// JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(options)
}

func getUserFromBody(r *http.Request, w http.ResponseWriter) (Login, error) {
	decoder := json.NewDecoder(r.Body)
	var l Login
	err := decoder.Decode(&l)
	if err != nil {
		http.Error(w, "no valid user details provided", 500)
	}
	return l, err
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	l, err := getUserFromBody(r, w)
	if err != nil {
		return
	}
	user := datastore.GetUser(l.Username) // Get the user

	// Get the session data stored from the function above
	session := datastore.GetSession(l.Username)

	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		http.Error(w, "registration failed", 500)
		return
	}

	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.
	user.AddCredential(*credential)
	fmt.Fprintf(w, "Registration Success")
}

// =======================
// Logging into an account
// =======================
//

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	l, err := getUserFromBody(r, w)
	if err != nil {
		return
	}
	user := datastore.GetUser(l.Username) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		// Handle Error and return.

		return
	}

	// store the session values
	user.SaveSession(session)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(options)
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	l, err := getUserFromBody(r, w)
	if err != nil {
		return
	}
	user := datastore.GetUser(l.Username) // Find the user

	// Get the session data stored from the function above
	session := datastore.GetSession(l.Username)

	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		// Handle Error and return.

		return
	}

	// Handle credential.Authenticator.CloneWarning

	// If login was successful, update the credential object
	// Pseudocode to update the user credential.
	user.UpdateCredential(*credential)

	fmt.Fprintf(w, "Login Success")
}
