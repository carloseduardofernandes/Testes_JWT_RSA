using Jose;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using static ConsoleApp_Testes_Aleatorios.JwksModel;

namespace ConsoleApp_Testes_Aleatorios
{
    class Program
    {
        static void Main(string[] args)
        {
            var retorno = ExtractPublicKeyFromJWT();

            if (string.IsNullOrEmpty(retorno.message))
                ProcessarRequisicaoSuspensao();
        }

        //SITE TOP MUITO BEM EXPLICADO OS CONCEITOS ENVOLVIDOS:
        //https://redthunder.blog/2017/06/08/jwts-jwks-kids-x5ts-oh-my/
        //https://medium.com/tableless/entendendo-tokens-jwt-json-web-token-413c6d1397f6
        //https://github.com/dvsekhvalnov/jose-jwt#verifying-and-decoding-tokens
        https://pt.coredump.biz/questions/38794670/how-to-create-encrypted-jwt-in-c-using-rs256-with-rsa-private-key
        private static RetornoModel ExtractPublicKeyFromJWT()
        {
            try
            {
                string token_str = $"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHRfc3NsX2tleSJ9.ew0KICAiaXNzIjogImh0dHBzOi8vYXBpLWRlcy5iYW5jb3ZvdG9yYW50aW0uY29tLmJyOjQ0MyIsDQogICJpYXQiOjE2MjA4NDU5NDksDQogICJhdWQiOiJsN3h4OTQwNDYxOTdmZTIxNDBjODllN2FjOTRkYmExY2NlZDQiLA0KICAiZXhwIjoxNjIwODQ5NTQ5LA0KICAianRpIjoiNDFiNmI5ZmYtMTFiOS00YjE2LTgyZGYtZGJjNTViOTc4NTg2IiwNCiAgInRva2VuX2RldGFpbHMiOiB7DQogICAgInNjb3BlIjoib29iIiwNCiAgICAiZXhwaXJlc19pbiI6MzYwMCwNCiAgICAidG9rZW5fdHlwZSI6IkJlYXJlciIsDQogICAgInVzZXJuYW1lIjoiIiwNCiAgICAicm9sZXMiOiIiDQogIH0NCn0.D2v7lIq2MMcaIVyld9Gnj4hIZV0ZdotON2Q6Jlg7HLunvajjlcUNA9_dPnL5M72gV82XEVZBHEP4-II23ap5NZdqUaj41e44BQw-SjN6CCTsUiJ3MH34Zb2ZQL6VQnI8GExpqvMV_w9lKTVpnz0_CUccZ2s0uHZELgqxJECokSeJ2ead44dE1NmRcqJKyM3qHkjjh36z5WiZ6rXAXRqeP0g5iUX2noqU1SrRbjSMxw0pzPgp5WiTT45wTYoU7PCLytb8EiBatMXcG_3jwF_MG52vEUVcNUHkGKxLhDJF_vuA_9q0rRQXVLT6_eyLoEfi9hYFE8gu54uxdoIFNYxSYg";

                //valida (se ele contém uma estrutura bem formada)
                try
                {
                    //aqui se der erro porque não está de acordo com formato jwt
                    //usando pacote System.IdentityModel.Tokens.Jwt
                    var token_mapeado = new JwtSecurityToken(token_str);

                    var assignature = Base64Url.Decode(token_mapeado.RawSignature);

                    //valida se emissor(iss/issuer) é o banco BV
                    if (token_mapeado.Payload.Iss != "https://api-des.bancovotorantim.com.br:443")
                        return new RetornoModel() { code = "99", message = $"Emissor(iss) não é o banco BV!" };

                    //Valida se está dentro da validade
                    if (UnixTimeStampToDateTime(Convert.ToDouble(token_mapeado.Payload.Exp)) < DateTime.Now.ToLocalTime())
                        return new RetornoModel() { code = "99", message = $"Token Expirado!" };

                    //Valida se chave publica BV da url jwks corresponde ao token jwt enviado na requisição atual
                    if (!validatePublicKeyJWT(token_str))
                        return new RetornoModel() { code = "99", message = $"Assinatura do Token não está correta!" };
                }
                catch (Exception e)
                {
                    return new RetornoModel() { code = "99", message = $"Token não tem uma estrutura bem formada!" };
                }

                return new RetornoModel();
            }
            catch (Exception e)
            {
                return new RetornoModel() { code = "99", message = $"Erro desconhecido ao validar Token!\n{e.Message}" };
            }
        }

        // Validate token with a public RSA key published by the IDP as a list of JSON Web Keys (JWK)
        //fonte: https://github.com/dvsekhvalnov/jose-jwt#verifying-and-decoding-tokens
        private static bool validatePublicKeyJWT(string token)
        {
            try
            {
                var client = new RestClient("https://api-des.bancovotorantim.com.br/");
                var request = new RestRequest("openid/connect/jwks.json", DataFormat.Json);
                var response = client.Get(request);

                var jwk = JsonConvert.DeserializeObject<Jwks_BV>(response.Content).keys[0];

                var key = new RSACryptoServiceProvider();

                //segundo stack overflow validando com os atributos 'n' e 'e' já basta, pois eles são usados para fornar a puplic key:
                //O atributo x5c contém a cadeia de certificação.
                //A primeira entrada do array x5c deve corresponder ao valor da chave representado pelos outros valores no JWK,
                //neste caso 'n' e 'e', portanto, a chave pública extraída x5c[0] e construída com 'n' e 'e' deve ser exatamente a mesma
                //FONTE: https://stackoverflow.com/questions/44639891/verifying-jwt-signature-using-public-key-endpoint

                key.ImportParameters(new RSAParameters
                {
                    Modulus = Base64Url.Decode(jwk.n),
                    Exponent = Base64Url.Decode(jwk.e)
                });

                //valida usando a chave rsa criada com 'n' e 'e', se der execption e porque não bateu a assinatura
                //usando pacote jose-jwt
                var paylod = Jose.JWT.Decode(token, key);

                //Aqui fazemos uma outra validação so para garantir mesmo,
                //verificamos se a public key BV está contida na primeira entrada do atributo x5c(geralmente aqui que ela fica)
               // if(jwk.x5c[0].Contains())

                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

        private static void ProcessarRequisicaoSuspensao()
        {
            var teste = "CONTINUAR ROTINAS";
        }
    }
}
