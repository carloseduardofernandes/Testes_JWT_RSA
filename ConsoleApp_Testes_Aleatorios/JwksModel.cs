using System;
using System.Collections.Generic;
using System.Text;

namespace ConsoleApp_Testes_Aleatorios
{
    public class JwksModel
    {
        // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse); 
        public class Key
        {
            public string kty { get; set; }
            public string kid { get; set; }
            public string use { get; set; }
            public string n { get; set; }
            public string e { get; set; }
            public List<string> x5c { get; set; }
            public string x5t { get; set; }
        }

        public class Jwks_BV
        {
            public List<Key> keys { get; set; }
        }


    }
}
