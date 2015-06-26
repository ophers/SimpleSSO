# SimpleSSO
A .Net class to implement a general-purpose simple SSO scheme.

## How it came to be?
We host our information systems on-premise and avail them to customers as a SaaS service.
A customer asked that we link to another application of his such that he whould not need to authenticate to it seperately. Both application of course have different authentication authorities, but it was accepted that we whould be authoritative for the purpose of this linking.  
The only question was how to implement this. OAuth 2.0, CAS and SAML 2.0 were deemed an overkill. A simple secure and reliable scheme is described by (one of many) this thread [SSO via HMAC and shared key](http://security.stackexchange.com/questions/51263/sso-via-hmac-and-shared-key-can-this-be-improved).
Googling for ready made implementations I only came across specifically tailored implementations: specific kind of encoding, user-data, ticket timeout etc.  

## Features
- Has six parameters controling its functionality and behaviour.
- Self contained and simple public interface.
- One line of code to initialize, one to create a token and one to validate a token.

## Usage
1. Exchange a shared key with your partner.
2. Instantiate an object with the shared key:
  `SimpleSSO sso = new SimpleSSO("My super secret Shared KEY :)");`
3. Create a token and use it:
  `string token = sso.CreateToken("jhondoe", "jhondoe@example.com");`
4. On the recieving side validate the token:
~~~{.cs}
string token = ...
if (sso.IsValid(token))
{
  // Do something useful
  string[] data = token.Split(':');
  // data[0] == "jhondoe", data[1] == "jhondoe@example.com"
}
~~~
