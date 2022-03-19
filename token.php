<?php
    
    function generateToken($username){
        //Generates a session token
        $secret = "your-secret-here";
        $header = base64_encode(json_encode(array(
            "alg" => "HS256",
            "typ" => "JWT"
        )));

        $payload = base64_encode(json_encode(array(
            "expire" => time() + 604800000,
            "username" => $username
        )));
        
        $x = json_encode(array(
            "alg" => "HS256",
            "typ" => "JWT"
        ));
        $sig = hash_hmac('sha256', $header . '.' . $payload, $secret);

        return $header . '.' . $payload . '.' . $sig;
    }

    function validateToken($token){

        //Determines if a session token is valid or not
        $secret = "your-secret-here";

        $tokenExplode = explode('.', $token);
        $header  = $tokenExplode[0];
        $payload = $tokenExplode[1];
        $signature = $tokenExplode[2];
        
        $headerData = json_decode(base64_decode($header));
        $payloadData = json_decode(base64_decode($payload));


        $newSig = hash_hmac('sha256', $header . '.' . $payload, $secret);

            
        return ((strcmp($newSig, $signature) != 0) && ($payloadData->expire < time()));
    }

    function getJWTData($token) {
        $explodedToken = explode('.', $token);
        $header = $explodedToken[0];
        $payload = $explodedToken[1];
        $signature = $explodedToken[2];

        return array(
            0 => json_decode(base64_decode($header)),
            1 => json_decode(base64_decode($payload)),
            2 => json_decode(base64_decode($signature))
        );
    }

    function checkIfValidJWT($token) {
        $explodedToken = explode('.', token);
        $header = $explodedToken[0];
        $payload = $explodedToken[1];
        $sig = $explodedToken[2];

        if (!is_string($token)) return false;
        if (count($explodedToken) != 3) return false;
        
        if (!base64_encode(base64_decode($sig)) == $sig) return false;
        if (!base64_encode(base64_decode($header)) == $header) return false;
        if (!base64_encode(base64_decode($payload)) == $payload) return false;
        
        $sig = json_decode($sig);
        $headerJson = json_decode($header);
        $payloadJson = json_decode($payload);

        if (json_last_error() != JSON_ERROR_NONE) return false;
        
        return true;
    }

?>
