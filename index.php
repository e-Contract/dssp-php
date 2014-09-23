<html>
    <head>
        <title>DSS test</title>
    </head>
    <body>
        <h1>DSS test</h1>
        <?php
        include_once "dssp/dssp.php";

        session_start();

        $dssClient = new DigitalSignatureServiceClient("https://localhost/dss-ws/dss");
        $pdf_handle = fopen("document.pdf", "r");
        $pdfData = fread($pdf_handle, 65536);
        fclose($pdf_handle);
        $session = $dssClient->uploadDocument($pdfData, "application/pdf", "test", "test");
        $_SESSION["DigitalSignatureServiceSession"] = $session;

        // change next landingUrl according to your setup
        $landingUrl = "https://localhost/~fcorneli/dss/landing.php";
        $visibleSignature = new VisibleSignature(1, 50, 100);
        $PendingRequest = $dssClient->createPendingRequest($session, $landingUrl, "en", TRUE, "CTO", "Vilvoorde", $visibleSignature);
        ?>

        <form name="BrowserPostForm" method="post"
              action="https://localhost/dss-ws/start">
            <input type="hidden" name="PendingRequest" value="<?= $PendingRequest ?>"/>
            <input type="submit" value="Submit"/>
        </form>
    </body>
</html>
