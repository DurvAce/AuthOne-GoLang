package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

// Configuration variables
var (
	oktaDomain    string
	clientID      string
	clientSecret  string
	redirectURI   string
	authEndpoint  string
	authzEndpoint string
	tokenURL      string

	sfdcDomain       string
	sfdcClientID     string
	sfdcClientSecret string
	sfdcRedirectUri  string
	sfdcTokenURL     string
	redirectURL      string
	redirectURLAuth0 string

	// authDomain      string
	// authClientID    string
	// authRedirectUri string
	// authTokenURL    string
)

// Initialize configuration variables after .env is loaded
func initConfig() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found, using system environment variables")
	}

	// Okta Configuration
	oktaDomain = getEnv("OKTA_DOMAIN")
	clientID = getEnv("OKTA_CLIENT_ID")
	clientSecret = getEnv("OKTA_CLIENT_SECRET")
	redirectURI = getEnv("OKTA_REDIRECT_URI")
	authEndpoint = oktaDomain + "/api/v1/authn"
	authzEndpoint = oktaDomain + "/oauth2/default/v1/authorize"
	tokenURL = oktaDomain + "/oauth2/default/v1/token"

	// Salesforce Configuration
	sfdcDomain = getEnv("SFDC_DOMAIN")
	sfdcClientID = getEnv("SFDC_CLIENT_ID")
	sfdcClientSecret = getEnv("SFDC_CLIENT_SECRET")
	sfdcRedirectUri = getEnv("SFDC_REDIRECT_URI")
	sfdcTokenURL = sfdcDomain + "/services/oauth2/token"
	redirectURL = getEnv("REDIRECT_URL")
	redirectURLAuth0 = getEnv("REDIRECT_URL_AUTH0")

	// https://dev-pqfdrdo9.us.auth0.com
	// authDomain = getEnv("AUTH_DOMAIN")
	//BcnRiVa4hushC3R27fBLJW1Jtit24Khx
	// authClientID = getEnv("AUTH_CLIENT_ID")
	// http://localhost:8080/auth0callback
	// authRedirectUri = getEnv("AUTH_REDIRECT_URI")
	//  /oauth/token
	// authTokenURL = sfdcDomain + "/oauth/token"
}

func getEnv(key string) string {
	isProd := false
	if host, exists := os.LookupEnv("HOST_ENV"); exists && (host == "production" || host == "prod") {
		isProd = true
	}

	envLogOnce.Do(func() {
		if isProd {
			log.Println("Running in PRODUCTION environment")
		} else {
			log.Println("Running in LOCAL/DEVELOPMENT environment")
		}
	})	

	if isProd && (key == "REDIRECT_URL" || key == "REDIRECT_URL_AUTH0") {
		prodKey := "PROD_" + key
		if value, exists := os.LookupEnv(prodKey); exists && value != "" {
			return value
		}
		log.Printf("Warning: Production environment variable %s is not set or empty", prodKey)
	}

	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}

	log.Printf("Warning: Environment variable %s is not set or empty", key)
	return ""
}

// Create a sync.Once to ensure we only log the environment once
var envLogOnce sync.Once

// LoginRequest represents user credentials received from frontend
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Handler for login API
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	log.Println("Request body:", string(body))

	var loginReq LoginRequest
	err = json.Unmarshal(body, &loginReq)
	if err != nil {
		log.Println("Error parsing JSON:", err)
		http.Error(w, "Failed to parse request JSON", http.StatusBadRequest)
		return
	}
	log.Println("Username:", loginReq.Username, "Password length:", len(loginReq.Password))

	if loginReq.Username == "" || loginReq.Password == "" {
		log.Println("Empty username or password")
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Step 1: Get sessionToken from Okta
	payload := fmt.Sprintf(`{"username":"%s", "password":"%s", "options":{"multiOptionalFactorEnroll":false,"warnBeforePasswordExpired":false}}`,
		loginReq.Username, loginReq.Password)

	req, err := http.NewRequest("POST", authEndpoint, strings.NewReader(payload))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to contact Okta", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, _ := io.ReadAll(resp.Body)

	// Handle authentication failure
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Authentication failed: "+string(respBody), resp.StatusCode)
		return
	}

	// Extract session token
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	sessionToken, ok := result["sessionToken"].(string)
	if !ok {
		http.Error(w, "Failed to retrieve sessionToken", http.StatusInternalServerError)
		return
	}

	// Step 2: Redirect user to Okta Authorization URL
	authRedirectURL := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=openid profile email&redirect_uri=%s&state=random123&sessionToken=%s",
		authzEndpoint, clientID, url.QueryEscape(redirectURI), sessionToken)

	log.Println("Redirection URL to get auth code:", authRedirectURL)
	http.Redirect(w, r, authRedirectURL, http.StatusFound)
}

// Callback handler for receiving the authorization code
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Callback URL hit!")
	code := r.URL.Query().Get("code")
	idp_provider := r.URL.Query().Get("idp_provider")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}
	log.Println("Authorization code received:", code)

	// Exchange authorization code for ID token
	var idToken string
	var err error
	if idp_provider == "" {
		idToken, err = exchangeCodeForToken(code)
	} else {
		idToken, err = exchangeCodeForTokenSFDC(code)
	}
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("id_token received:", idToken)
	// Set the ID token as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "id_token",
		Value: idToken,
		Path:  "/",
	})

	log.Println("Redirecting to the success page")
	// Redirect to success page
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Auth0 Callback URL hit!")
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}
	log.Println("Authorization code received:", code)

	// Exchange authorization code for ID token
	var idToken string
	var err error

	idToken, err = auth0ExchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("auth0 id_token received:", idToken)
	// Set the ID token as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "id_token",
		Value: idToken,
		Path:  "/",
	})

	log.Println("Redirecting to the success page")
	// Redirect to success page
	http.Redirect(w, r, redirectURLAuth0, http.StatusFound)
}

func auth0ExchangeCodeForToken(code string) (string, error) {

	fmt.Println("Auth0 Flow")
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	// authClientID
	data.Set("client_id", "BcnRiVa4hushC3R27fBLJW1Jtit24Khx")
	// authRedirectUri
	data.Set("redirect_uri", "http://localhost:8080/auth0callback")
	data.Set("code", code)
	data.Set("code_verifier", "SjYw4eLcJZkN2w6L4eHyVNSE3iuLG7rnlkcakh7omPg")

	// authDomain+authTokenURL
	resp, err := http.PostForm("https://dev-pqfdrdo9.us.auth0.com/oauth/token", data)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %v", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %v", err)
	}

	// Parse JSON response
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	// Extract ID token
	idToken, _ := tokenResponse["id_token"].(string)
	accessToken, exists := tokenResponse["access_token"].(string)
	log.Println("id_token  received: ", idToken)
	log.Println("\naccess_token  received: ", accessToken)

	if !exists {
		return "", fmt.Errorf("ID token not found in response")
	}

	return idToken, nil
}

func tenantsHandler(w http.ResponseWriter, r *http.Request) {
	// Calling validate api
	url := "https://qa.saasalta.global/session/sso/validate"
	cookie, _ := r.Cookie("id_token")
	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set headers
	authorization := "Bearer " + cookie.Value
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", authorization)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println("Validate Response:\n", string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

type RequestPayload struct {
	Authorization string `json:"Authorization"`
}

func entitlementHandler(w http.ResponseWriter, r *http.Request) {

	baseURL := "https://qa.saasalta.global/session/sso/login"
	cookie, _ := r.Cookie("id_token")

	orgId := r.URL.Query().Get("orgId")
	tenantId := r.URL.Query().Get("tenantId")

	// Setting params
	params := url.Values{}
	params.Set("orgName", orgId)
	params.Set("tenantId", tenantId)

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	//fmt.Println(cookie.Value)
	payload := RequestPayload{
		Authorization: cookie.Value,
	}

	// creating Payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}
	//fmt.Println(string(jsonData))

	// Setting API Request
	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Setting headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Making API request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	//Getting bady from response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Logging response
	//fmt.Println("Login Response Body:", string(body))

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write JSON response
	w.Write(body)
}

// Okta : Function to exchange authorization code for an ID token
func exchangeCodeForToken(code string) (string, error) {
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("code", code)

	// Send POST request to Okta token endpoint
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %v", err)
	}

	// Parse JSON response
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	// Extract ID token
	idToken, exists := tokenResponse["id_token"].(string)
	if !exists {
		return "", fmt.Errorf("ID token not found in response")
	}

	return idToken, nil
}

// SFDC : Function to exchange authorization code for an ID token
func exchangeCodeForTokenSFDC(code string) (string, error) {
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", sfdcClientID)
	data.Set("client_secret", sfdcClientSecret)
	data.Set("redirect_uri", sfdcRedirectUri)
	data.Set("code", code)

	// Send POST request to Okta token endpoint
	resp, err := http.PostForm(sfdcTokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	fmt.Println("SFDC received code: ", string(body))
	if err != nil {
		return "", fmt.Errorf("failed to read sfdc token response: %v", err)
	}

	// Parse JSON response
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse sfdc token response: %v", err)
	}
	fmt.Println("sfdc tokenResponse:", tokenResponse)

	// Extract ID token
	idToken, exists := tokenResponse["id_token"].(string)
	if !exists {
		return "", fmt.Errorf("SFDC ID token not found in response")
	}

	return idToken, nil
}

// Success page
func successHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Login Successful!")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from Angular frontend
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "http://localhost:4200" // Default to Angular dev server
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600") // Cache preflight response for 1 hour

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func loginHandler_2(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	var loginReq LoginRequest
	err = json.Unmarshal(body, &loginReq)
	if err != nil {
		http.Error(w, "Failed to parse request JSON", http.StatusBadRequest)
		return
	}

	// Step 1: Get sessionToken from Okta
	payload := fmt.Sprintf(`{"username":%q, "password":%q, "options":{"multiOptionalFactorEnroll":false,"warnBeforePasswordExpired":false}}`,
		loginReq.Username, loginReq.Password)

	req, err := http.NewRequest("POST", authEndpoint, strings.NewReader(payload))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error contacting Okta:", err)
		http.Error(w, "Failed to contact Okta", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, _ := io.ReadAll(resp.Body)

	// Check for authentication failure
	if resp.StatusCode != http.StatusOK {
		log.Println("Authentication failed:", string(respBody))
		http.Error(w, "Authentication failed: "+string(respBody), resp.StatusCode)
		return
	}

	// Extract session token
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	sessionToken, ok := result["sessionToken"].(string)
	if !ok {
		http.Error(w, "Failed to retrieve sessionToken", http.StatusInternalServerError)
		return
	}
	log.Println("Session token received")

	// Step 2: Create a custom HTTP client that DOESN'T follow redirects
	// This is crucial - we need to capture the redirect URL
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Request authorization code
	authRequestURL := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=openid%%20profile%%20email&redirect_uri=%s&state=random123&sessionToken=%s",
		authzEndpoint, clientID, url.QueryEscape(redirectURI), sessionToken)

	log.Println("Auth request URL:", authRequestURL)
	authReq, err := http.NewRequest("GET", authRequestURL, nil)
	if err != nil {
		http.Error(w, "Failed to create auth request", http.StatusInternalServerError)
		return
	}

	authResp, err := noRedirectClient.Do(authReq)
	if err != nil {
		http.Error(w, "Failed to contact Okta Auth Server", http.StatusInternalServerError)
		return
	}
	defer authResp.Body.Close()

	// Get redirect URL which contains the authorization code
	location := authResp.Header.Get("Location")
	if location == "" {
		log.Println("No redirect URL found in response")
		log.Println("Response status:", authResp.Status)
		log.Println("Response headers:", authResp.Header)
		respBody, _ := io.ReadAll(authResp.Body)
		log.Println("Response body:", string(respBody))
		http.Error(w, "No redirect URL found", http.StatusInternalServerError)
		return
	}

	log.Println("Redirect URL:", location)

	// Parse the redirect URL to extract code
	redirectURL, err := url.Parse(location)
	if err != nil {
		http.Error(w, "Failed to parse redirect URL", http.StatusInternalServerError)
		return
	}

	// Extract the code parameter
	code := redirectURL.Query().Get("code")
	if code == "" {
		log.Println("No authorization code found in redirect URL")
		log.Println("Redirect URL query parameters:", redirectURL.Query())
		http.Error(w, "No authorization code found in redirect URL", http.StatusInternalServerError)
		return
	}

	log.Println("Authorization code extracted from redirect URL:", code)

	// Step 3: Exchange authorization code for ID token
	idToken, err := exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("ID token received successfully")

	// Return ID token to client along with the redirect URL for debugging
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id_token":     idToken,
		"redirect_url": location,
	})
}

func main() {
	// Initialize configuration
	initConfig()

	// Create a new router
	mux := http.NewServeMux()

	// Register handlers - we'll primarily use the loginHandler_2 approach
	mux.HandleFunc("/api/login", loginHandler_2) // This is what Angular will call

	// Keep these for backward compatibility or direct browser testing
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/auth0callback", authCallbackHandler)
	mux.HandleFunc("/success", successHandler)
	mux.HandleFunc("/tenants", tenantsHandler)
	mux.HandleFunc("/entitlements", entitlementHandler)

	// Wrap the router with improved CORS middleware
	corsHandler := corsMiddleware(mux)

	fmt.Println("✅ Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", corsHandler))
}
