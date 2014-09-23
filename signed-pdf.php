<?php
session_start();
header("Content-type: application/pdf");
header('Content-Disposition: attachment; filename="signed.pdf"');
$pdfData = $_SESSION["SignedPDF"];
echo $pdfData;

