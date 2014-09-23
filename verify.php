<html>
    <head>
        <title>DSS verify test</title>
    </head>
    <body>
        <h1>DSS verify test</h1>
        <?php
        include_once "dssp/dssp.php";

        $dssClient = new DigitalSignatureServiceClient();
        
        $pdf_handle = fopen("document-1.pdf", "r");
        $pdfData = fread($pdf_handle, 65536);
        fclose($pdf_handle);

        $verificationResult = $dssClient->verify($pdfData);
        echo "<p>Renew timestamp before: " . $verificationResult->renewTimeStampBefore . "</p>";
        echo "<table>";
        foreach ($verificationResult->signatureInfos as $signatureInfo) {
            echo "<tr>";
            echo "<td>" . $signatureInfo->signingTime . "</td>";
            echo "<td>" . $signatureInfo->subject . "</td>";
            echo "</tr>";
        }
        echo "</table>";
        
        $pdf_handle = fopen("document-2.pdf", "r");
        $pdfData = fread($pdf_handle, 128*1024);
        fclose($pdf_handle);

        $verificationResult = $dssClient->verify($pdfData);
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
    </body>
</html>