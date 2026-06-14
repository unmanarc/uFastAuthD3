// ============================================================
// Login State - Global variables and configuration
// ============================================================

let decodedRedirectURI = "";
let loggedIn = false;
let loggedInGETParsedParam = true;
let currentScheme = null;
let schemesAvailable = [];
let cachedCookieData = null;
let sessionKeepAuthenticated = false;
const urlParams = new URLSearchParams(window.location.search);

// Retrieve parameters from URL
const mode = urlParams.get('mode');
const encodedRedirectURI = urlParams.get('redirectURI');


//const appName = urlParams.get('app');
