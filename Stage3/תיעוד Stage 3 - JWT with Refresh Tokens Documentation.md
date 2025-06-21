# תיעוד Stage 3—JWT with Refresh Tokens Documentation

<div dir="rtl">

## השוואה בין Stage 2 ל-Stage 3

### מה היה ב-Stage 2:
- JWT Access Token בלבד
- תוקף של 5 דקות
- אחרי תפוגה - צריך login מחדש
- AuthenticationResponse עם accessToken בלבד

### מה נוסף ב-Stage 3:
- **Refresh Token System** - מערכת חידוש tokens
- **Dual Token Strategy** - Access Token + Refresh Token
- **RefreshTokenService** - שירות לחידוש tokens
- **Endpoint חדש** - POST /api/refresh_token
- **Extended Sessions** - session ארוך יותר ללא login חוזר
- **Better UX** - משתמש לא מנותק כל 5 דקות

## ארכיטקטורת המערכת - System Architecture

</div>

```mermaid
graph TB
    Client[Client Application<br/>React on localhost:5173]
    
    subgraph SpringBoot["Spring Boot Application - Stage 3"]
        direction TB
        AuthController[AuthenticationController<br/>POST /api/login<br/>POST /api/refresh_token]
        UserController[UserController<br/>GET /api/protected-message]
        AuthService[AuthenticationService]
        RefreshService[RefreshTokenService<br/>NEW IN STAGE 3]
        UserService[CustomUserDetailsService]
        JwtUtil[JwtUtil<br/>generateAccessToken<br/>generateRefreshToken]
        JwtFilter[JwtAuthenticationFilter<br/>shouldNotFilter added]
        Security[SecurityConfig<br/>permitAll refresh_token]
        
        subgraph Database["Database Layer"]
            UserRepo[UserRepository]
            RoleRepo[RoleRepository]
            UserEntity[User Entity]
            RoleEntity[Role Entity]
        end
        
        subgraph DTOs["Data Transfer Objects"]
            AuthRequest[AuthenticationRequest]
            AuthResponse[AuthenticationResponse<br/>accessToken + refreshToken]
            RefreshRequest[RefreshTokenRequest<br/>NEW IN STAGE 3]
        end
    end
    
    MySQL[(MySQL Database<br/>schema_jwt_2024)]
    
    Client -->|1. POST /api/login| AuthController
    Client -->|3. POST /api/refresh_token| AuthController
    Client -->|5. GET /api/protected-message + Access Token| UserController
    
    AuthController -->|Login| AuthService
    AuthController -->|Refresh| RefreshService
    
    AuthService --> UserService
    AuthService --> JwtUtil
    RefreshService --> UserService
    RefreshService --> JwtUtil
    
    UserService --> UserRepo
    UserRepo --> UserEntity
    UserEntity --> RoleEntity
    RoleEntity --> RoleRepo
    
    UserRepo --> MySQL
    RoleRepo --> MySQL
    
    AuthController --> DTOs
    UserController --> DTOs
```

<div dir="rtl">

## זרימת Dual Token Authentication - Dual Token Flow

</div>

```mermaid
sequenceDiagram
    participant Client
    participant AuthController as AuthenticationController
    participant AuthService as AuthenticationService
    participant RefreshService as RefreshTokenService
    participant JwtUtil
    participant UserService as CustomUserDetailsService
    participant DB as MySQL Database
    
    Note over Client, DB: Initial Login Flow
    Client->>AuthController: POST /api/login {username, password}
    AuthController->>AuthService: authenticate(request)
    AuthService->>UserService: loadUserByUsername(username)
    UserService->>DB: findByUsername(username)
    DB-->>UserService: User with roles
    UserService-->>AuthService: UserDetails
    AuthService->>AuthService: validatePassword()
    
    AuthService->>JwtUtil: generateAccessToken(userDetails)
    JwtUtil-->>AuthService: Access Token (5 min)
    AuthService->>JwtUtil: generateRefreshToken(userDetails)
    JwtUtil-->>AuthService: Refresh Token (10 min)
    
    AuthService-->>AuthController: AuthenticationResponse(accessToken, refreshToken)
    AuthController-->>Client: 200 OK {accessToken, refreshToken}
    
    Note over Client, DB: Using Access Token
    Client->>AuthController: GET /api/protected-message<br/>Authorization: Bearer <accessToken>
    AuthController-->>Client: 200 OK Protected content
    
    Note over Client, DB: Access Token Expires (after 5 minutes)
    Client->>AuthController: GET /api/protected-message<br/>Authorization: Bearer <expiredAccessToken>
    AuthController-->>Client: 401 Unauthorized
    
    Note over Client, DB: Refresh Token Flow
    Client->>AuthController: POST /api/refresh_token {refreshToken}
    AuthController->>RefreshService: refreshTokens(refreshToken)
    RefreshService->>JwtUtil: isTokenExpired(refreshToken)
    
    alt Refresh Token Valid
        JwtUtil-->>RefreshService: false (not expired)
        RefreshService->>JwtUtil: extractUsername(refreshToken)
        JwtUtil-->>RefreshService: username
        RefreshService->>UserService: loadUserByUsername(username)
        UserService-->>RefreshService: UserDetails
        
        RefreshService->>JwtUtil: generateAccessToken(userDetails)
        JwtUtil-->>RefreshService: New Access Token (5 min)
        RefreshService->>JwtUtil: generateRefreshToken(userDetails)
        JwtUtil-->>RefreshService: New Refresh Token (10 min)
        
        RefreshService-->>AuthController: AuthenticationResponse(newAccessToken, newRefreshToken)
        AuthController-->>Client: 200 OK {accessToken, refreshToken}
        
    else Refresh Token Expired
        JwtUtil-->>RefreshService: true (expired)
        RefreshService-->>AuthController: null
        AuthController-->>Client: 401 Unauthorized "Please login again"
    end
    
    Note over Client, DB: Continue with New Access Token
    Client->>AuthController: GET /api/protected-message<br/>Authorization: Bearer <newAccessToken>
    AuthController-->>Client: 200 OK Protected content
```

<div dir="rtl">

## תרשים Token Lifecycle - Token Management

</div>

```mermaid
stateDiagram-v2
    [*] --> Login: User provides credentials
    Login --> TokensGenerated: Successful authentication
    
    state TokensGenerated {
        AccessToken: Access Token (5 min)
        RefreshToken: Refresh Token (10 min)
    }
    
    TokensGenerated --> AccessValid: Use Access Token
    
    state AccessValid {
        ProtectedRequest: Make API calls with Access Token
        ProtectedRequest --> ProtectedRequest: Valid responses
    }
    
    AccessValid --> AccessExpired: After 5 minutes
    
    state AccessExpired {
        state refresh_choice <<choice>>
        refresh_choice --> RefreshValid: Refresh Token still valid
        refresh_choice --> RefreshExpired: Refresh Token expired
    }
    
    RefreshValid --> RefreshProcess: POST /api/refresh_token
    
    state RefreshProcess {
        ValidateRefresh: Validate Refresh Token
        GenerateNew: Generate new tokens
        ValidateRefresh --> GenerateNew
    }
    
    RefreshProcess --> TokensGenerated: New tokens issued
    RefreshExpired --> [*]: Must login again
    
    note right of TokensGenerated
        Access Token: 5 minutes
        Refresh Token: 10 minutes
        Total session: up to 10 minutes
        without re-authentication
    end note
```

<div dir="rtl">

## תרשים מחלקות מעודכן - Updated Class Diagram

</div>

```mermaid
classDiagram
    class AuthenticationController {
        -AuthenticationService authenticationService
        -RefreshTokenService refreshTokenService
        +authenticateUser(AuthenticationRequest) ResponseEntity
        +refreshToken(RefreshTokenRequest) ResponseEntity
    }
    
    class UserController {
        +home() String
    }
    
    class AuthenticationService {
        -CustomUserDetailsService userDetailsService
        -JwtUtil jwtUtil
        -PasswordEncoder passwordEncoder
        +authenticate(AuthenticationRequest) AuthenticationResponse
    }
    
    class RefreshTokenService {
        -UserRepository userRepository
        -CustomUserDetailsService userDetailsService
        -JwtUtil jwtUtil
        +refreshTokens(String) AuthenticationResponse
    }
    
    class CustomUserDetailsService {
        -UserRepository userRepository
        +loadUserByUsername(String) UserDetails
        -mapRolesToAuthorities(List~Role~) Collection~GrantedAuthority~
    }
    
    class JwtUtil {
        -Key key
        +generateAccessToken(UserDetails) String
        +generateRefreshToken(UserDetails) String
        +validateToken(String, UserDetails) boolean
        +extractUsername(String) String
        +isTokenExpired(String) Boolean
        +extractExpiration(String) Date
        -extractClaim(String, Function) T
        -extractAllClaims(String) Claims
        -getKey() Key
    }
    
    class JwtAuthenticationFilter {
        -JwtUtil jwtUtil
        -CustomUserDetailsService userDetailsService
        +shouldNotFilter(HttpServletRequest) boolean
        +doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain) void
    }
    
    class SecurityConfig {
        -JwtUtil jwtUtil
        -CustomUserDetailsService userDetailsService
        +passwordEncoder() PasswordEncoder
        +filterChain(HttpSecurity) SecurityFilterChain
    }
    
    class User {
        -Long id
        -String username
        -String password
        -List~Role~ roles
    }
    
    class Role {
        -Long id
        -String roleName
        -List~User~ users
    }
    
    class AuthenticationRequest {
        -String username
        -String password
    }
    
    class AuthenticationResponse {
        -String accessToken
        -String refreshToken
    }
    
    class RefreshTokenRequest {
        -String refreshToken
    }
    
    class JwtProperties {
        +EXPIRATION_TIME long
        +IDLE_TIME long
        +REFRESH_EXPIRATION_TIME long
        +TOKEN_PREFIX String
        +HEADER_STRING String
    }
    
    class UserRepository {
        +findByUsername(String) User
        +findUserByUsername(String) User
    }
    
    class RoleRepository {
        +findRolesByUserId(Long) List~Role~
        +findByRoleName(String) Optional~Role~
    }
    
    AuthenticationController --> AuthenticationService
    AuthenticationController --> RefreshTokenService
    AuthenticationController --> AuthenticationRequest
    AuthenticationController --> AuthenticationResponse
    AuthenticationController --> RefreshTokenRequest
    
    AuthenticationService --> CustomUserDetailsService
    AuthenticationService --> JwtUtil
    AuthenticationService --> AuthenticationRequest
    AuthenticationService --> AuthenticationResponse
    
    RefreshTokenService --> CustomUserDetailsService
    RefreshTokenService --> JwtUtil
    RefreshTokenService --> UserRepository
    RefreshTokenService --> AuthenticationResponse
    
    CustomUserDetailsService --> UserRepository
    CustomUserDetailsService --> User
    CustomUserDetailsService --> Role
    
    JwtUtil --> JwtProperties
    
    JwtAuthenticationFilter --> JwtUtil
    JwtAuthenticationFilter --> CustomUserDetailsService
    JwtAuthenticationFilter --> JwtProperties
    
    SecurityConfig --> JwtUtil
    SecurityConfig --> CustomUserDetailsService
    SecurityConfig --> JwtAuthenticationFilter
    
    UserRepository --> User
    RoleRepository --> Role
    User --> Role
```

<div dir="rtl">

## הגדרות JWT מעודכנות - Updated JWT Configuration

</div>

```mermaid
graph TD
    JwtProperties[JwtProperties Configuration]
    
    subgraph TimeSettings["Time Settings"]
        ExpTime[EXPIRATION_TIME<br/>300,000 ms = 5 minutes<br/>Access Token lifespan]
        IdleTime[IDLE_TIME<br/>300,000 ms = 5 minutes<br/>Additional idle time]
        RefreshTime[REFRESH_EXPIRATION_TIME<br/>600,000 ms = 10 minutes<br/>EXPIRATION_TIME + IDLE_TIME]
    end
    
    subgraph HeaderSettings["Header Settings"]
        TokenPrefix[TOKEN_PREFIX<br/>Bearer ]
        HeaderString[HEADER_STRING<br/>Authorization]
    end
    
    subgraph TokenTypes["Token Types Generated"]
        AccessToken[Access Token<br/>5 minutes<br/>For API calls]
        RefreshToken[Refresh Token<br/>10 minutes<br/>For token renewal]
    end
    
    subgraph FilterConfig["Filter Configuration"]
        FilterChain[SecurityFilterChain]
        JwtFilterPos[JwtAuthenticationFilter]
        ShouldNotFilter[shouldNotFilter method<br/>Skips /login and /refresh_token]
        AuthRules[Authorization Rules<br/>permitAll: /api/login, /api/refresh_token<br/>hasAnyRole: /api/protected-message]
    end
    
    JwtProperties --> TimeSettings
    JwtProperties --> HeaderSettings
    TimeSettings --> TokenTypes
    HeaderSettings --> FilterConfig
    TokenTypes --> FilterConfig
    JwtFilterPos --> ShouldNotFilter
```

<div dir="rtl">

## תרשים Data Flow המעודכן - Updated Data Flow

</div>

```mermaid
flowchart TD
    Start([Client needs access])
    HasTokens{Has valid<br/>Access Token?}
    UseAccess[Use Access Token<br/>for API calls]
    CallSuccess{API call<br/>successful?}
    Success[Continue using<br/>Access Token]
    
    TokenExpired{Access Token<br/>expired?}
    HasRefresh{Has valid<br/>Refresh Token?}
    
    RefreshFlow[POST /api/refresh_token<br/>with Refresh Token]
    RefreshSuccess{Refresh<br/>successful?}
    GetNewTokens[Receive new<br/>Access + Refresh tokens]
    
    LoginFlow[POST /api/login<br/>with credentials]
    LoginSuccess{Login<br/>successful?}
    GetInitialTokens[Receive initial<br/>Access + Refresh tokens]
    
    Error[Authentication Error<br/>Access Denied]
    
    Start --> HasTokens
    HasTokens -->|Yes| UseAccess
    HasTokens -->|No| LoginFlow
    
    UseAccess --> CallSuccess
    CallSuccess -->|200 OK| Success
    CallSuccess -->|401 Unauthorized| TokenExpired
    
    TokenExpired --> HasRefresh
    HasRefresh -->|Yes| RefreshFlow
    HasRefresh -->|No| LoginFlow
    
    RefreshFlow --> RefreshSuccess
    RefreshSuccess -->|Yes| GetNewTokens
    RefreshSuccess -->|No| LoginFlow
    
    GetNewTokens --> UseAccess
    
    LoginFlow --> LoginSuccess
    LoginSuccess -->|Yes| GetInitialTokens
    LoginSuccess -->|No| Error
    
    GetInitialTokens --> UseAccess
    
    Success --> HasTokens
```

<div dir="rtl">

## השוואת התכונות - Feature Comparison

</div>

```mermaid
graph LR
    subgraph Stage2["Stage 2 - Single Token"]
        S2Login[Login → Access Token]
        S2Access[Use Access Token]
        S2Expire[Token Expires → Login Again]
        S2Flow[User Experience:<br/>Frequent re-authentication]
        
        S2Login --> S2Access
        S2Access --> S2Expire
        S2Expire --> S2Login
    end
    
    subgraph Stage3["Stage 3 - Dual Token"]
        S3Login[Login → Access + Refresh Token]
        S3Access[Use Access Token]
        S3Expire[Access Token Expires]
        S3Refresh[Use Refresh Token → New Tokens]
        S3Continue[Continue seamlessly]
        S3Final[Final expiry → Login Again]
        S3Flow[User Experience:<br/>Seamless token renewal]
        
        S3Login --> S3Access
        S3Access --> S3Expire
        S3Expire --> S3Refresh
        S3Refresh --> S3Continue
        S3Continue --> S3Access
        S3Refresh --> S3Final
        S3Final --> S3Login
    end
    
    Stage2 -.->|Upgrade| Stage3
```

<div dir="rtl">

## מתודולוגיית Refresh Token ב-Stage 3

### 1. Initial Authentication
- משתמש מתחבר עם username/password
- מערכת מחזירה 2 tokens: Access (5 דקות) + Refresh (10 דקות)
- Client שומר את שני הtokens

### 2. API Usage Phase
- Client משתמש ב-Access Token לבקשות API
- כל בקשה מוצלחת מאריכה את השימוש
- לא צריך לחדש כלום כל עוד Access Token תקף

### 3. Access Token Expiration
- אחרי 5 דקות Access Token פג
- API calls מחזירים 401 Unauthorized
- Client מזהה שצריך לחדש token

### 4. Token Refresh Process
- Client שולח Refresh Token ל-/api/refresh_token
- מערכת בודקת תקינות וterm של Refresh Token
- אם תקף: מחזירה צמד tokens חדש
- אם פג: משתמש צריך להתחבר מחדש

### 5. Extended Session Management
- כל refresh מחזיר tokens חדשים
- מאפשר session רציף עד 10 דקות
- משפר UX משמעותית
- מקטין עומס על שרת authentication

## יתרונות Stage 3

### Security Benefits:
- **Short-lived Access Tokens** - חשיפה מוגבלת
- **Longer session duration** - UX טוב יותר
- **Token rotation** - tokens חדשים בכל refresh
- **Granular control** - שליטה נפרדת על כל סוג token

### User Experience Benefits:
- **Seamless usage** - פחות הפרעות למשתמש
- **Background refresh** - Client יכול לחדש אוטומטית
- **Extended sessions** - פחות logins חוזרים
- **Better mobile experience** - משמעותי לאפליקציות mobile

### Technical Benefits:
- **Scalable architecture** - מבנה יותר מתקדם
- **Industry standard** - OAuth 2.0 pattern
- **Flexible timing** - שליטה נפרדת בזמני תפוגה
- **Clear separation** - access vs refresh concerns

</div>