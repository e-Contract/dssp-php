<?php

/**
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */
include_once 'xmlseclibs.php';

class BinarySecretType {

    public $_;
    public $Type;

}

class DocumentType {

    var $Base64Data;

}

class Base64Data {

    var $MimeType;

}

/**
 * PHP client for the Digital Signature Service protocol.
 */
class DigitalSignatureServiceClient {

    private $location;

    /**
     * Main constructor.
     * @param string $location the location of the DSS web service. Defaults to the e-contract.be DSS instance.
     */
    function __construct($location = "https://www.e-contract.be/dss-ws/dss") {
        $this->location = $location;
    }

    private function psha1($clientSecret, $serverSecret, $sizeBits = 256) {
        $sizeBytes = $sizeBits / 8;

        $hmacKey = $clientSecret;
        $hashSize = 160; // HMAC_SHA1 length is always 160
        $bufferSize = $hashSize / 8 + strlen($serverSecret);
        $i = 0;

        $b1 = $serverSecret;
        $b2 = "";
        $temp = null;
        $psha = array();

        while ($i < $sizeBytes) {
            $b1 = hash_hmac('SHA1', $b1, $hmacKey, true);
            $b2 = $b1 . $serverSecret;
            $temp = hash_hmac('SHA1', $b2, $hmacKey, true);

            for ($j = 0; $j < strlen($temp); $j++) {
                if ($i < $sizeBytes) {
                    $psha[$i] = $temp[$j];
                    $i++;
                } else {
                    break;
                }
            }
        }

        return implode("", $psha);
    }

    /**
     * Uploads a document to be signed to the DSS web service.
     * 
     * The optional application credentials are used by the DSS to activate branding 
     * (company logo) and to activate custom PDF signature visualization profiles.
     * 
     * @param bytearray $data the document.
     * @param string $mimetype the optional mimetype of the document. Default is application/pdf.
     * @param string $username the optional application credential username.
     * @param string $password the optional application credential password.
     * @return DigitalSignatureServiceSession the DSSP session object.
     */
    public function uploadDocument($data, $mimetype = "application/pdf", $username = NULL, $password = NULL) {
        $client = new DSSSoapClient($username, $password, NULL, dirname(__FILE__) . "/wsdl/dssp-ws.wsdl", array("location" => $this->location,
            "soap_version" => SOAP_1_2,
            "trace" => 1,
            "style" => SOAP_DOCUMENT,
            "use" => SOAP_LITERAL,
            "classmap" => array(
                "Base64Data" => "Base64Data",
                "DocumentType" => "DocumentType",
                "BinarySecretType" => "BinarySecretType")));

        $params = new stdClass();
        $params->Profile = "urn:be:e-contract:dssp:1.0";
        $additionalProfile = new SoapVar("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing", XSD_ANYURI, null, null, "AdditionalProfile", "urn:oasis:names:tc:dss:1.0:core:schema");
        $tokenType = new SoapVar("http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct", XSD_ANYURI, null, null, "TokenType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $requestType = new SoapVar("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue", XSD_ANYURI, null, null, "RequestType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $keySize = new SoapVar(256, XSD_UNSIGNEDINT, null, null, "KeySize", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $binarySecret = new BinarySecretType();
        $binarySecret->Type = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
        $clientEntropy = openssl_random_pseudo_bytes(16);
        $binarySecret->_ = $clientEntropy;
        $entropyContent = new SoapVar($binarySecret, XSD_ANYTYPE, "BinarySecretType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512", "BinarySecret", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $entropy = new SoapVar(
                new ArrayObject(array($entropyContent))
                , XSD_ANYTYPE, null, null, "Entropy", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $requestSecurityTokenContent = new ArrayObject(array($tokenType, $requestType, $keySize, $entropy));
        $requestSecurityToken = new SoapVar($requestSecurityTokenContent, XSD_ANYTYPE, null, null, "RequestSecurityToken", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        $params->OptionalInputs = new SoapVar(new ArrayObject(array($additionalProfile, $requestSecurityToken)), XSD_ANYTYPE);
        $document = new DocumentType();
        $document->Base64Data = new Base64Data();
        $document->Base64Data->MimeType = $mimetype;
        $document->Base64Data->_ = $data;
        $params->InputDocuments = new stdClass();
        $params->InputDocuments->Document = $document;

        $signResponse = $client->sign($params);

        $session = new DigitalSignatureServiceSession();

        $ResponseID = $signResponse->OptionalOutputs->any["ResponseID"];
        $session->responseId = $ResponseID;
        $RequestSecurityTokenResponseCollection = $signResponse->OptionalOutputs->any["RequestSecurityTokenResponseCollection"];
        $sctIdentifier = $RequestSecurityTokenResponseCollection->RequestSecurityTokenResponse->any["RequestedSecurityToken"]->any["SecurityContextToken"]->any["Identifier"];
        $session->sctIdentifier = $sctIdentifier;
        $sctId = $RequestSecurityTokenResponseCollection->RequestSecurityTokenResponse->any["RequestedSecurityToken"]->any["SecurityContextToken"]->Id;
        $session->sctId = $sctId;
        $serverEntropy = $RequestSecurityTokenResponseCollection->RequestSecurityTokenResponse->any["Entropy"]->any["BinarySecret"]->_;
        $secret = $this->psha1($clientEntropy, $serverEntropy);
        $session->secret = $secret;
        return $session;
    }

    private function addVisibleSignatureExtension($xml, $optionalInputs, $signerRole, $signerLocation, $visibleSignature) {
        if ($signerRole === NULL && $signerLocation === NULL && $visibleSignature === NULL) {
            return;
        }
        $visibleSignatureConfiguration = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureConfiguration");
        $optionalInputs->appendChild($visibleSignatureConfiguration);
        $visibleSignatureConfiguration->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:vs', 'urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#');
        $visibleSignatureConfiguration->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignaturePolicy", "DocumentSubmissionPolicy"));

        if ($visibleSignature !== NULL) {
            $visibleSignaturePosition = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignaturePosition");
            $visibleSignatureConfiguration->appendChild($visibleSignaturePosition);
            $visibleSignaturePosition->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
            $visibleSignaturePosition->setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "vs:PixelVisibleSignaturePositionType");
            $pageNumber = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:PageNumber", $visibleSignature->getPage());
            $visibleSignaturePosition->appendChild($pageNumber);
            $x = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:x", $visibleSignature->getX());
            $visibleSignaturePosition->appendChild($x);
            $y = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:y", $visibleSignature->getY());
            $visibleSignaturePosition->appendChild($y);
        }

        $visibleSignatureItemsConfiguration = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureItemsConfiguration");
        $visibleSignatureConfiguration->appendChild($visibleSignatureItemsConfiguration);

        if ($signerLocation !== NULL) {
            $visibleSignatureItem = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureItem");
            $visibleSignatureItemsConfiguration->appendChild($visibleSignatureItem);
            $visibleSignatureItem->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemName", "SignatureProductionPlace"));
            $itemValue = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue");
            $itemValue->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
            $itemValue->setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "vs:ItemValueStringType");
            $itemValue->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue", $signerLocation));
            $visibleSignatureItem->appendChild($itemValue);
        }
        if ($signerRole !== NULL) {
            $visibleSignatureItem = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureItem");
            $visibleSignatureItemsConfiguration->appendChild($visibleSignatureItem);
            $visibleSignatureItem->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemName", "SignatureReason"));
            $itemValue = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue");
            $itemValue->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
            $itemValue->setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "vs:ItemValueStringType");
            $itemValue->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue", $signerRole));
            $visibleSignatureItem->appendChild($itemValue);
        }
        if ($visibleSignature !== NULL) {
            $visibleSignatureItem = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureItem");
            $visibleSignatureItemsConfiguration->appendChild($visibleSignatureItem);
            $visibleSignatureItem->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemName", "SignerImage"));
            $itemValue = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue");
            $itemValue->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
            $itemValue->setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "vs:ItemValueURIType");
            $itemValue->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue", $visibleSignature->getSignerImage()));
            $visibleSignatureItem->appendChild($itemValue);
            if ($visibleSignature->getCustomText() !== NULL) {
                $visibleSignatureItem = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:VisibleSignatureItem");
                $visibleSignatureItemsConfiguration->appendChild($visibleSignatureItem);
                $visibleSignatureItem->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemName", "CustomText"));
                $itemValue = $xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue");
                $itemValue->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
                $itemValue->setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "vs:ItemValueStringType");
                $itemValue->appendChild($xml->createElementNS("urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#", "vs:ItemValue", $visibleSignature->getCustomText()));
                $visibleSignatureItem->appendChild($itemValue);
            }
        }
    }

    /**
     * Creates a signed DSSP pending request.
     * 
     * The resulting string should be placed within an HTML form for POST redirection towards the DSS.
     * 
     * @param DigitalSignatureServiceSession $session the DSSP session object.
     * @param string $landingUrl the URL of the landing page within your web application.
     * @param string $language the optional language that the DSS should use in the interface.
     * @param boolean $returnSignerIdentity the optional flag to indicate that the DSS should return the signer identity.
     * @param string $signerRole the optional signer role.
     * @param string $signerLocation the optional signer location.
     * @return string the base64 encoded pending request.
     */
    public function createPendingRequest($session, $landingUrl, $language = NULL, $returnSignerIdentity = FALSE, $signerRole = NULL, $signerLocation = NULL, $visibleSignature = NULL) {
        $xml = new DOMDocument();
        $pendingRequest = $xml->createElementNS("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0", "async:PendingRequest");
        $pendingRequest->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:async', 'urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0');
        $pendingRequest->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:dss', 'urn:oasis:names:tc:dss:1.0:core:schema');
        $pendingRequest->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsa', 'http://www.w3.org/2005/08/addressing');
        $pendingRequest->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xml->appendChild($pendingRequest);

        $optionalInputs = $xml->createElementNS("urn:oasis:names:tc:dss:1.0:core:schema", "dss:OptionalInputs");
        $pendingRequest->appendChild($optionalInputs);

        $optionalInputs->appendChild($xml->createElementNS("urn:oasis:names:tc:dss:1.0:core:schema", "dss:AdditionalProfile", "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing"));
        $optionalInputs->appendChild($xml->createElementNS("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0", "async:ResponseID", $session->responseId));
        $messageId = uniqid("uuid:");
        $optionalInputs->appendChild($xml->createElementNS("http://www.w3.org/2005/08/addressing", "wsa:MessageID", $messageId));

        $timestamp = $xml->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Timestamp");
        $optionalInputs->appendChild($timestamp);
        $created = new DateTime("NOW", new DateTimeZone("UTC"));
        $timestamp->appendChild($xml->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Created", $created->format(DateTime::ISO8601)));
        $expires = $created->add(new DateInterval('P0DT0H5M0S'));
        $timestamp->appendChild($xml->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Expires", $expires->format(DateTime::ISO8601)));
        $replyTo = $xml->createElementNS("http://www.w3.org/2005/08/addressing", "wsa:ReplyTo");
        $optionalInputs->appendChild($replyTo);
        $replyTo->appendChild($xml->createElementNS("http://www.w3.org/2005/08/addressing", "wsa:Address", $landingUrl));

        if ($language !== NULL) {
            $optionalInputs->appendChild($xml->createElementNS("urn:oasis:names:tc:dss:1.0:core:schema", "dss:Language", $language));
        }

        if ($returnSignerIdentity) {
            $optionalInputs->appendChild($xml->createElementNS("urn:oasis:names:tc:dss:1.0:core:schema", "dss:ReturnSignerIdentity"));
        }

        $this->addVisibleSignatureExtension($xml, $optionalInputs, $signerRole, $signerLocation, $visibleSignature);

        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objDSig->addReference($xml, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            "http://www.w3.org/2001/10/xml-exc-c14n#"), array("force_uri" => TRUE));

        $objKey = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
        $objKey->loadKey($session->secret);

        $objDSig->sign($objKey, $optionalInputs);

        $securityTokenReference = $xml->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:SecurityTokenReference");
        $securityTokenReference->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $reference = $xml->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Reference");
        $reference->setAttribute("ValueType", "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct");
        $reference->setAttribute("URI", $session->sctIdentifier);
        $securityTokenReference->appendChild($reference);
        $objDSig->appendToKeyInfo($securityTokenReference);

        return base64_encode($xml->saveXML());
    }

    /**
     * Checks the incoming SignResponse message.
     * 
     * @param string $signResponse the base64 encoded SignResponse message.
     * @param DigitalSignatureServiceSession $session the DSSP session object.
     * @return SignResponseResult information on the signature process.
     * @throws Exception in case the sign response message is not OK.
     * @throws UserCancelledException in case the end-user cancelled the signing process.
     */
    public function checkSignResponse($signResponse, $session) {
        $doc = new DOMDocument();
        $doc->loadXML(base64_decode($signResponse));

        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($doc);
        if (!$objDSig) {
            throw new Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedInfo();

        $retVal = $objXMLSecDSig->validateReference();

        if (!$retVal) {
            throw new Exception("Reference Validation Failed");
        }
        $objKey = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
        $objKey->loadKey($session->secret);

        if (!$objXMLSecDSig->verify($objKey)) {
            throw new Exception("signature verification failed.");
        }

        $xp = new DOMXPath($doc);
        $xp->registerNamespace('dss', 'urn:oasis:names:tc:dss:1.0:core:schema');
        $resultMajor = $xp->query("/dss:SignResponse/dss:Result/dss:ResultMajor/text()")->item(0)->wholeText;
        if (strcmp("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending", $resultMajor) != 0) {
            if (strcmp("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError", $resultMajor) == 0) {
                $resultMinorNodeList = $xp->query("/dss:SignResponse/dss:Result/dss:ResultMinor/text()");
                if ($resultMinorNodeList->length != 0) {
                    $resultMinor = $resultMinorNodeList->item(0)->wholeText;
                    if (strcmp("urn:be:e-contract:dssp:1.0:resultminor:user-cancelled", $resultMinor) == 0) {
                        throw new UserCancelledException();
                    }
                }
            }
            throw new Exception("incorrect ResultMajor");
        }

        $signerIdentityNodeList = $xp->query("/dss:SignResponse/dss:OptionalOutputs/dss:SignerIdentity/text()");
        $signerIdentity;
        if ($signerIdentityNodeList->length != 0) {
            $signerIdentity = $signerIdentityNodeList->item(0)->wholeText;
        } else {
            $signerIdentity = NULL;
        }
        $signResponseResult = new SignResponseResult($signerIdentity);
        return $signResponseResult;
    }

    /**
     * Downloads the signed document.
     * 
     * @param DigitalSignatureServiceSession $session the DSSP session object.
     * @return bytearray the signed document.
     * @throws Exception in case something goes wrong.
     */
    public function downloadSignedDocument($session) {
        $client = new DSSSoapClient(NULL, NULL, $session, dirname(__FILE__) . "/wsdl/dssp-ws.wsdl", array("location" => $this->location,
            "soap_version" => SOAP_1_2,
            "trace" => 1,
            "style" => SOAP_DOCUMENT,
            "use" => SOAP_LITERAL));

        $pendingRequest = new stdClass();
        $pendingRequest->Profile = "urn:be:e-contract:dssp:1.0";
        $additionalProfile = new SoapVar("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing", XSD_ANYURI, null, null, "AdditionalProfile", "urn:oasis:names:tc:dss:1.0:core:schema");
        $responseId = new SoapVar($session->responseId, XSD_STRING, null, null, "ResponseID", "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0");
        $pendingRequest->OptionalInputs = new SoapVar(new ArrayObject(array($additionalProfile, $responseId)), XSD_ANYTYPE);

        $signResponse = $client->pendingRequest($pendingRequest);

        $resultMajor = $signResponse->Result->ResultMajor;
        if (strcmp("urn:oasis:names:tc:dss:1.0:resultmajor:Success", $resultMajor) != 0) {
            throw new Exception("not successful");
        }

        $data = $signResponse->OptionalOutputs->any["DocumentWithSignature"]->Document->Base64Data->_;
        return $data;
    }

    /**
     * Verifies the signatures on the document.
     * 
     * @param bytearray $data the document.
     * @param string $mimetype the mimetype of the document.
     * @return VerificationResult the signature verification result object.
     * @throws Exception
     */
    public function verify($data, $mimetype = "application/pdf") {
        $client = new SoapClient(dirname(__FILE__) . "/wsdl/dssp-ws.wsdl", array("location" => $this->location,
            "soap_version" => SOAP_1_2,
            "trace" => 1,
            "style" => SOAP_DOCUMENT,
            "use" => SOAP_LITERAL,
            "classmap" => array(
                "Base64Data" => "Base64Data",
                "DocumentType" => "DocumentType")));

        $verifyRequest = new stdClass();
        $verifyRequest->Profile = "urn:be:e-contract:dssp:1.0";
        $document = new DocumentType();
        $document->Base64Data = new Base64Data();
        $document->Base64Data->MimeType = $mimetype;
        $document->Base64Data->_ = $data;
        $verifyRequest->InputDocuments = new stdClass();
        $verifyRequest->InputDocuments->Document = $document;

        $verifyResponse = $client->verify($verifyRequest);

        $resultMajor = $verifyResponse->Result->ResultMajor;
        if (strcmp("urn:oasis:names:tc:dss:1.0:resultmajor:Success", $resultMajor) != 0) {
            throw new Exception("not successful");
        }

        $verificationResult = new VerificationResult();
        $verificationResult->renewTimeStampBefore = $verifyResponse->OptionalOutputs->any["TimeStampRenewal"]->Before;

        if (is_array($verifyResponse->OptionalOutputs->any["VerificationReport"]->IndividualReport)) {
            $verificationResult->signatureInfos = array();
            foreach ($verifyResponse->OptionalOutputs->any["VerificationReport"]->IndividualReport as $individualReport) {
                $signingTime = $individualReport->SignedObjectIdentifier->SignedProperties->SignedSignatureProperties->SigningTime;
                $subject = $individualReport->Details->any["DetailedSignatureReport"]->CertificatePathValidity->PathValidityDetail->CertificateValidity->Subject;
                $signatureInfo = new SignatureInfo();
                $signatureInfo->signingTime = $signingTime;
                $signatureInfo->subject = $subject;
                array_push($verificationResult->signatureInfos, $signatureInfo);
            }
        } else {
            $signingTime = $verifyResponse->OptionalOutputs->any["VerificationReport"]->IndividualReport->SignedObjectIdentifier->SignedProperties->SignedSignatureProperties->SigningTime;
            $subject = $verifyResponse->OptionalOutputs->any["VerificationReport"]->IndividualReport->Details->any["DetailedSignatureReport"]->CertificatePathValidity->PathValidityDetail->CertificateValidity->Subject;

            $signatureInfo = new SignatureInfo();
            $signatureInfo->signingTime = $signingTime;
            $signatureInfo->subject = $subject;
            $verificationResult->signatureInfos = array($signatureInfo);
        }

        return $verificationResult;
    }

}

/**
 * Contains configuration parameters for visible PDF signatures.
 */
class VisibleSignature {

    /**
     * A visible signature profile based on the eID photo.
     */
    const EID_PHOTO_SIGNER_IMAGE = "urn:be:e-contract:dssp:1.0:vs:si:eid-photo";

    /**
     * A visible signature profile based on the eID photo as watermark.
     * This visible signature profile also includes information about the signatory: role, location and optional custom text.
     */
    const EID_PHOTO_SIGNER_INFO_SIGNER_IMAGE = "urn:be:e-contract:dssp:1.0:vs:si:eid-photo:signer-info";

    private $page;
    private $x;
    private $y;
    private $signerImage;
    private $customText;

    /**
     * Sets configuration parameters for visible PDF signatures.
     * 
     * @param integer $page the page on which to place the visible signature. Starts at 1.
     * @param integer $x the x coordinate where to place the visible signature.
     * @param integer $y the y coordinate where to place the visible signature.
     * @param string $signerImage the signer image profile URI. See the constants.
     * @param string $customText the optional custom text.
     */
    function __construct($page, $x, $y, $signerImage = EID_PHOTO_SIGNER_IMAGE, $customText = NULL) {
        $this->page = $page;
        $this->x = $x;
        $this->y = $y;
        $this->signerImage = $signerImage;
        $this->customText = $customText;
    }

    public function getPage() {
        return $this->page;
    }

    public function getX() {
        return $this->x;
    }

    public function getY() {
        return $this->y;
    }

    public function getSignerImage() {
        return $this->signerImage;
    }

    public function getCustomText() {
        return $this->customText;
    }

}

class SignResponseResult {

    private $signerIdentity;

    function __construct($signerIdentity) {
        $this->signerIdentity = $signerIdentity;
    }

    public function getSignerIdentity() {
        return $this->signerIdentity;
    }

}

class VerificationResult {

    public $renewTimeStampBefore;
    public $signatureInfos;

}

class SignatureInfo {

    public $signingTime;
    public $subject;

}

class DigitalSignatureServiceSession {

    public $responseId;
    public $sctIdentifier;
    public $sctId;
    public $secret;

}

/**
 * Thrown in case the end-user cancelled the signing operation.
 */
class UserCancelledException extends Exception {
    
}

class DSSSoapClient extends SoapClient {

    private $session;
    private $username;
    private $password;

    public function DSSSoapClient($username, $password, $session, $wsdl, array $options = null) {
        parent::SoapClient($wsdl, $options);
        $this->session = $session;
        $this->username = $username;
        $this->password = $password;
    }

    public function __doRequest($request, $location, $action, $version, $one_way = 0) {
        $domRequest = new DOMDocument();
        $domRequest->loadXML($request);

        $soapPrefix = $domRequest->documentElement->prefix;

        $xp = new DOMXPath($domRequest);
        $xp->registerNamespace('soap', 'http://www.w3.org/2003/05/soap-envelope');
        $header = $xp->query('/soap:Envelope/soap:Header');
        if ($header->length == 0) {
            $header = $domRequest->createElementNS("http://www.w3.org/2003/05/soap-envelope", $soapPrefix . ":Header");
            $envelope = $xp->query("/soap:Envelope")->item(0);
            $body = $xp->query("/soap:Envelope/soap:Body")->item(0);
            $envelope->insertBefore($header, $body);
        } else {
            $header = $header->item(0);
        }
        $security = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Security");
        $security->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        $security->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $security->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsc', 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512');
        $header->appendChild($security);

        if ($this->session !== NULL) {
            $timestamp = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Timestamp");
            $timestamp->setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id", "TS");
            $security->appendChild($timestamp);
            $created = new DateTime("NOW", new DateTimeZone("UTC"));
            $timestamp->appendChild($domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Created", $created->format(DateTime::W3C)));
            $expires = $created->add(new DateInterval('P0DT0H5M0S'));
            $timestamp->appendChild($domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Expires", $expires->format(DateTime::W3C)));

            $body = $xp->query("/soap:Envelope/soap:Body")->item(0);
            $body->setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id", "B");
            $body->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

            $securityContextToken = $domRequest->createElementNS("http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512", "wsc:SecurityContextToken");
            $security->appendChild($securityContextToken);
            $securityContextToken->setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id", $this->session->sctId);
            $identifier = $domRequest->createElementNS("http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512", "wsc:Identifier", $this->session->sctIdentifier);
            $securityContextToken->appendChild($identifier);

            $objDSig = new XMLSecurityDSig();
            $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
            $objDSig->addReference($timestamp, XMLSecurityDSig::SHA1, array(
                "http://www.w3.org/2001/10/xml-exc-c14n#"), array("overwrite" => FALSE,
                "prefix_ns" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"));
            $objDSig->addReference($body, XMLSecurityDSig::SHA1, array(
                "http://www.w3.org/2001/10/xml-exc-c14n#"), array("overwrite" => FALSE,
                "prefix_ns" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"));
            $objKey = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
            $secret = $this->session->secret;
            $objKey->loadKey($secret);
            $objDSig->sign($objKey, $security);

            $securityTokenReference = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:SecurityTokenReference");
            $securityTokenReference->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
            $reference = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Reference");
            $reference->setAttribute("URI", "#" . $this->session->sctId);
            $securityTokenReference->appendChild($reference);
            $objDSig->appendToKeyInfo($securityTokenReference);
        }

        if ($this->username !== NULL) {
            $usernameToken = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:UsernameToken");
            $security->appendChild($usernameToken);
            $usernameToken->appendChild($domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Username", $this->username));
            $passwordElement = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Password", $this->password);
            $passwordElement->setAttributeNS(NULL, "Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
            $usernameToken->appendChild($passwordElement);

            $timestamp = $domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Timestamp");
            $timestamp->setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id", "TS");
            $security->appendChild($timestamp);
            $created = new DateTime("NOW", new DateTimeZone("UTC"));
            $timestamp->appendChild($domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Created", $created->format(DateTime::W3C)));
            $expires = $created->add(new DateInterval('P0DT0H5M0S'));
            $timestamp->appendChild($domRequest->createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Expires", $expires->format(DateTime::W3C)));
        }

        $request = $domRequest->saveXML();
        return parent::__doRequest($request, $location, $action, $version, $one_way);
    }

}
