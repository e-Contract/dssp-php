<html>
    <head>
        <title>DSS test</title>
    </head>
    <body>
        <h1>DSS test</h1>
        <?php
        /*
         * Example usage of the DSSP PHP SDK.
         */

        include_once "dssp/dssp.php";

        session_start();
        header('Set-Cookie: PHPSESSID=' . session_id() . '; SameSite=None; Secure');

        $dssInstance = "https://www.e-contract.be/dss-ws/";
        //$dssInstance = "http://localhost/dss-ws/";
        $location = $dssInstance . "dss";
        $dssClient = new DigitalSignatureServiceClient($location);
        $pdf_handle = fopen("document.pdf", "r");
        $pdfData = fread($pdf_handle, 65536);
        fclose($pdf_handle);
        $session = $dssClient->uploadDocument($pdfData, "application/pdf");
        $_SESSION["DigitalSignatureServiceSession"] = $session;

        $landingUrl = $dssClient->rel2abs("landing.php");

        $visibleSignature = new VisibleSignature(1, 50, 100, VisibleSignature::EID_PHOTO_SIGNER_INFO_SIGNER_IMAGE, "1234");
        $PendingRequest = $dssClient->createPendingRequest($session, $landingUrl, "en", TRUE, "CTO", "Beersel", $visibleSignature);
        $postLocation = $dssInstance . "start";
        //$postLocation = "https://localhost/dss-ws/start";
        ?>

        <form name="BrowserPostForm" method="post"
              action="<?= $postLocation ?>">
            <input type="hidden" name="PendingRequest" value="<?= $PendingRequest ?>"/>
            <input type="submit" value="Submit"/>
        </form>
    </body>
</html>
