<html>
    <head>
        <title>DSS test landing</title>
    </head>
    <body>
        <h1>DSS test landing</h1>
        <p>
            <a href="./">back</a>
        </p>
        <?php
        /*
         * This page is where the DSS lands after creation of the signature.
         */

        include_once 'dssp/dssp.php';

        session_start();

        $session = $_SESSION["DigitalSignatureServiceSession"];

        $signResponse = $_POST["SignResponse"];

        $dssInstance = "https://www.e-contract.be/dss-ws/";
        //$dssInstance = "http://localhost/dss-ws/";
        $location = $dssInstance . "dss";
        $dssClient = new DigitalSignatureServiceClient($location);
        $signResponseResult;
        try {
            $signResponseResult = $dssClient->checkSignResponse($signResponse, $session);
        } catch (UserCancelledException $e) {
            echo "<p>User Cancelled</p>";
            die();
        }

        $pdfData = $dssClient->downloadSignedDocument($session);
        $_SESSION["SignedPDF"] = $pdfData;

        $verificationResult = $dssClient->verify($pdfData);
        echo "<p>Signer identity: " . $signResponseResult->getSignerIdentity() . "</p>";
        echo "<p>Renew timestamp before: " . $verificationResult->renewTimeStampBefore . "</p>";
        echo "<table>";
        foreach ($verificationResult->signatureInfos as $signatureInfo) {
            echo "<tr>";
            echo "<td>" . $signatureInfo->signingTime . "</td>";
            echo "<td>" . $signatureInfo->subject . "</td>";
            echo "</tr>";
        }
        echo "</table>";
        ?>
        <a href="signed-pdf.php">Download signed PDF</a>
    </body>
</html>