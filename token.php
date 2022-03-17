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

            
        if (strcmp($newSig, $signature) !== 0){
            return false;
        }

        return $payloadData->expire < time();
    }


?>
