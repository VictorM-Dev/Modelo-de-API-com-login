# Modelo de API com sistema de usuários

Nesse README está descrito apenas as funções principais de como utilizar o sistema de geração de tokens, e autenticação de login. São explicadas as classes:

- `SecurityConfig`
- `TokenService`
- `UsuarioController` - apenas os métodos de login e cadastro

*Faça a importação de todas as dependências se quiser aprender a utilizar as classes de forma correta, e não apenas clonar o repositório.*

# Organização do projeto

## Dependências usadas

- `Spring Web`
- `PostgreSQL Driver`
- `Spring Security`
- `OAuth Resource Server`
- `Spring Data JPA`

*Note que, estou ocultando todas as importações de dependências dentro das classes.*

## Arquitetura

Utiliza a arquitetura de camadas padrão, com os seguintes pacotes:

- `config` - Todas as configuração que não são gerenciadas normalmente pelo SpringBoot. Todos os `@Bean` .
- `controller` - Controladores que vão cuidar do fluxo de requisições HTTP.
- `dto` - Records para modelar os `@RequestBody` .
- `error` - Exceções personalizadas de `RuntimeException` .
- `model` - Todas as entidades da aplicação.
- `repository` - Todos os repositórios da aplicação.
- `service` - Todos os services da aplicação.

# Pacote `config`

## Classe `SecurityConfig`

### Configuração da geração de tokens

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {}
```

Criação padrão da classe das configurações de segurança, devidamente marcada com as anotações.

Configuração do método de retorno do `SecurityFilterChain` (vai substituir o padrão do SpringSecurity).

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
	http
		.authorizeHttpRequests(a -> a
			.requestMatchers("/cadastrar").permitAll()  // Endpoint definido no controller
			.requestMatchers("/login").permitAll()      // Endpoint definido no controller
			.anyRequest().authenticated())
		.oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
		.csrf(c -> c.disable())
		.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
	return http.build();
}

// Note as abreviações das funções lambdas
	// a - authorize
	// o - oauth2
	// c - csrf
	// s - session
// É apenas uma convenção de uso
```

O SpringBoot tem uma configuração de segurança padrão que usa sistema de login próprio para todas as requisições, então com o método `SecurityFilterChain` podemos configurar um padrão de segurança personalizada.

- O método recebe por padrão um objeto `HttpSecurity` que será configurado.
- A anotação `@Bean` serve para introduzir esse método dentro do padrão do SpringBoot

Configuração do objeto `http` :

- `authorizeHttpRequests()` - definição de autorização necessária para as requisições.
    - `requestMatchers(”/endpoint”).permitAll()` - Torna todas requisições para esse endpoint permitidas, ou seja, públicas.
    - `anyRequest().authenticated()` - Todas as outras requisições são tratadas como privadas e precisam de autorização.
- `oauth2ResourceServer()`- ativando o OAuth2 na aplicação.
    - `jwt()` - Valida o token JWT utilizando as configurações padrão:`Customizer.withDefaults()` .
- `csrf()` - Configuração padrão do Spring Security contra ataques  *CSRF.* (Essa API é totalmente `stateless`, então essa configuração pode e deve ser desativada).
    - `disable()` - Marca o `csrf` como desabilitado.
- `sessionManagement()` - Configuração do gerenciamento de sessão da API.
    - `sessionCreationPolicy(SessionCreationPolicy.STATELESS)` - Definição de uma aplicação totalmente STATELESS . *(Isso permite a desativação do `csrf` pois em uma aplicação STATELESS, nenhum cookie de sessão é usado).*

Por fim, retornamos o objeto `http` criado e configurado com o método `build()` que vai construir esse objeto com essas configurações definidas.

Configuração do token JWT:

```java
@Value("${jwt.private.key}")
private RSAPrivateKey privateKey;

@Value("${jwt.public.key}")
private RSAPublicKey publicKey;
```

- `@Value("${jwt.nome.do.arquivo}")` - Essa anotação indica para o Spring que ele deve pegar valor definido no `aplication.properties` .
- `private RSAPrivateKey privateKey;` - O Spring injeta o arquivo RSA fazendo a configuração automática se receber um arquivo `.pem` utilizando a dependência do OAuth2.

```css
jwt.private.key=classpath:key.private
jwt.public.key=classpath:key.public
```

- `jwt.nome.do.arquivo=classpath:caminho.do.arquivo` se o caminho absoluto não for definido, ele buscara na pasta de `resources` do projeto.

Configuração do encoder e decoder

```java
// Encoder
@Bean
public JwtEncoder jwtEncoder(){
	JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
	var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
	return new NimbusJwtEncoder(jwks);
}
```

O método `JwtEncoder` vai configurar o encoder do token JWT.

- `RSAKey.builder()` - Utiliza a chave pública RSA
    - `privateKey()` - Utiliza a chave privada RSA e constrói JWT com o`build()` .

      A chave pública é usada para validação, valida se o token foi gerado pela API, a chave privada é a assinatura do token, ela assina todos os tokens gerados pela API.

- `ImmutableJWKSet<>(new JWKSet(jwk))` - Cria um provedor imutável de chaves JWK, garantindo que o Spring possa validar e assinar os tokens.
- `NimbusJwtEncoder(jwks)` - Constrói o encoder responsável pela geração de tokens.

```java
// Decoder
@Bean
public JwtDecoder jwtDecoder(){
	return NimbusJwtDecoder.withPublicKey(publicKey).build();
}
```

O método simplesmente cria o decoder que usa a chave pública para validar o token de acesso.

### Configuração da codificação de senhas (formato `hash`)

```java
@Bean
public PasswordEncoder passwordEncoder(){
	return new BCryptPasswordEncoder();  // Aplica o algorítmo BCrypt para gerar o hash
}
```

O método acima apenas mostra ao Spring que injete a instância do `PasswordEncoder`onde precisar.  Essa dependência é usada para transformar a senha de `String` para `hash` e armazenar no banco.

# Pacote `service`

## Classe `TokenService`

```java
@Service
public class TokenService(){}
```

Criação da classe `TokenService`  com as anotações.

```java
private final JwtEncoder jwtEncoder;
public TokenService(JwtEncoder jwtEncoder){
	this.jwtEncoder = jwtEncoder;
}
```

Injeção da dependência do `JwtEncoder` dentro do `TokenService` .

O encoder foi configurado no pacote anterior com o `SecurityConfig` .

Configurações de criação do método de geração de token:

```java
public String gerarToken(UUID userID){
	var agora = Instant.now();
	var expiraEm = 3000L;
	JwtClaimsSet claims = JwtClaimsSet.builder()
		.issuer("VDev")
		.subject(userID.toString())
		.issuedAt(agora)
		.expiresAt(agora.plusSeconds(expiraEm))
		.build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
}
```

Utilizando a variável `agora` para pegar o tempo atual a partir da hora do sistema, e a variável `expiraEm` para definir o tempo em segundos que o token irá durar, nesse caso, irá durar 50 minutos.

O ideal é fazer um token de duração menor e usar um sistema de refresh token.

Para a configuração do `claims` :

- `.issuer()` - Normalmente usa-se o nome da aplicação, ou o nome do backend da aplicação.
- `.subject()` - Definimos o dono do token, nesse caso, utiliza-se o ID, já que o e-mail ou username podem ser alterados. O ID sempre permanece único para aquele usuário.
- `.issuedAt()` - Data de criação do token, passando a variável `agora` para definir que o token é gerado no momento da requisição de login.
- `.expiresAt()` - Data de quando o token irá expirar, passando o parâmetro `agora.plusSeconds(expiraEm)` para determinar que o token irá expirar 50 minutos após a sua criação. *(Depois desse tempo é necessário que o usuário faça o login novamente).*
- `.build()` - Assim como nas outras sessões, apenas constrói o objeto com a configuração definida acima.

Por fim, utilizamos o método do encode configurado anteriormente para gerar o token a partir dos parâmetros da `claim` definida.

# Pacote `controller`

## Classe `UsuarioController`

```java
@RestController
public class UsuarioController{}
```

Criação da classe `UsuarioController` com as devidas anotações.

*Não utilizei `@RequestMapping` para essa classe, pois o ideal é que ela controle apenas o login e o cadastro em requisições separadas.*

```java
private UsuarioService usuarioService;
private PasswordEncoder passwordEncoder;
private TokenService tokenService;
public UsuarioController(UsuarioService usuarioService, PasswordEncoder passwordEncoder, 
												 TokenService tokenService){
	this.usuarioService = usuarioService;
	this.passwordEncoder = passwordEncoder;
	this.tokenService = tokenService;
}
```

Injeção das dependências utilizadas nesse no `UsuarioController` .

Configurações para usar o endpoint `"/cadastrar"` :

```java
@PostMapping("/cadastrar")
public ResponseEntity<?> cadastrarUsuario(@RequestBody Usuario usuario){
	try{
		String senhaHash = passwordEncoder.encode(usuario.getSenha());
		usuario.setSenha(senhaHash);
		usuarioService.cadastrarUsuario(usuario);
		return ResponseEntity.ok().build();
	} catch (DuplicateEmailException e){
		return ResponseEntity.badRequest().body(e.getMessage());
	}
}
```

Uma requisição POST no endpoint `"/cadastrar"` que foi definido como público dentro da criação do objeto `http` do `SecurityConfig` .

*Esse método está utilizando exceções personalizadas a critério de estudo, porém se injetar a dependência `Validation` do SpringBoot, essas exceções podem ser substituídas pelas exceções lançadas pela anotação `@Valid` .*

- `passwordEncoder.encode()` - Transforma a senha em `hash` .
- `setSenha()` - Seta a senha `hash` no usuário cadastrado.
- `cadastrarUsuario()` - Método personalizado do `UsuarioService` para chamar a função `save()` do repositório, e gravar no banco de dados utilizando JPA/Hibernate do SpringBoot.

E por fim, se tudo correr bem, retorna uma `ResponseEntity.ok()` ou status 200.

Configurações para usar o endpoint `"/login"` :

```java
@PostMapping("/login")
public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest){
	try{
		String token = tokenService.gerarToken(
			usuarioService.autenticar(
				loginRequest.email(), loginRequest.senha()).getUsuarioID());
		return ResponseEntity.ok(token);
	} catch (UserNotFoundException | InvalidCredetialsException e){
		return ResponseEntity.status(401).body(e.getMessage());
	}
}
```

Note que o login também funciona como uma requisição POST no endpoint `"/login"` , que também foi definido como público dentro da criação do objeto `http` do `SecurityConfig` .

Esse método irá utilizar uma `@RequestBody` usando o `record` definido dentro `dto` .

*Assim como o método de cadastrar, utiliza exceções personalizadas.*

- `gerarToken()` - Método personalizado criado dentro do `TokenService` que recebe o `UUID` do usuário e retorna o token em formato de `String` .
    - `autenticar()` - Método personalizado que recebe as variáveis de login do usuário, nesse caso `email` e `senha` .

      O método `autenticar()` busca um usuário no banco através do método `findByEmail()` , ele seta a senha como `null` por segurança e retorna o usuário com aquele `email` .

      *Note que a variável de e-mail tem validação e garantia de unicidade.*

    - `getUsuarioID()` - Por fim o método pega o `UUID` do usuário e manda dentro do método `gerarToken()` .

Se tudo ocorrer bem, o método retorna uma `ResponseEntity.ok(token)` com o token enviado para o cliente HTTP.

# Como usar a API

## Fluxo de requisições

### POST - cadastrar

```json
{
  "email": "usuario@exemplo.com",
  "senha": "minhaSenha123"
}
```

Enviando o JSON acima para o endpoint `"/cadastrar"` será cadastrado um usuário com esse e-mail. A senha será transformada em `hash` e gravada no banco de dados com total segurança.

- Se existir um usuário com esse e-mail é retornado 400.

### POST- login

```json
{
  "email": "usuario@exemplo.com",
  "senha": "minhaSenha123"
}
```

Mandando a mesma requisição no endpoint `"/login"` será feito o login do usuário e retornado um token no formato JWT.

- Se o e-mail ou a senha estiverem incorretos é retornado 401, sem exemplificar qual credencial está incorreta.

## Criação de novas requisições privadas

Depois de montada com as duas requisições principais de login e cadastro definidas como pública, apenas alteramos as outras requisições para receber um novo parâmetro.

```java
@GetMapping("/teste")
public ResponseEntity<Usuario> exibirUsuario(JwtAuthenticationToken token){
	UUID userID = UUID.fromString(token.getName());
	Usuario usuarioNoBanco = usuarioService.findById(userID)
		.orElseThrow(() -> new /*exceção(mensagem)*/);
	// Não retorna a senha do usuário 
	usuarioNoBanco.setSenha(null);
	return ResponseEntity.ok(usuarioNoBanco);
}
```

Como o `subject()` da criação do token é o `UUID` , usando o `getName()` podemos recuperar esse valor da própria requisição.

Com esse padrão simples, é possível gerar qualquer requisição seguindo a autenticação via token criada no projeto.
# Bônus - Aplicando CORS no objeto `HTTP`

```java
.cors(cors -> cors.configurationSource(request -> {
	var config = new CorsConfiguration();
	config.setAllowedOrigins(List.of("http://127.0.0.1:5500"));
	config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
  config.setAllowedHeaders(List.of("*"));
  config.setAllowCredentials(true);
  return config;
}))
```

O CORS serve para configurar as requisições de origem cruzada. *O browser costuma bloquear requisições assim.*

Configurações de CORS:

- `cors()` - recebe uma função lambda com o parâmetro `configurationSource()` que recebe outra função lambda.
    - `setAllowedOrigins()` - recebe uma lista de todos os caminhos que podem fazer requisições a API.
    - `setAllowedMethods()` - recebe uma lista de todos os métodos que podem ser requeridos pelos caminhos definidos anteriormente.
    - `setAllowedHeaders()` - recebe uma lista de todos os headers que podem ser mandados;
    - `setAllowCredentials()` - definido como `true` permite que a API receba credências. *(como esse projeto é STATELESS, ele recebe apenas JWT como credencial).*

      *Note que utilizando o `true` precisamos definir uma origem e não podemos determinar ela com `"*"` .*


Note que também é possível inserir um `@CrossOrigin(origin = "caminho")` no começo de cada `controller` para permitir que ele receba requisições naquele endpoint.