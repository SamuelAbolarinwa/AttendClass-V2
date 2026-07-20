import { useEffect, useRef, useState, useCallback } from "react";
import * as faceapi from "@vladmandic/face-api";

export function useFaceDetection() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [modelsLoaded, setModelsLoaded] = useState(false);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [descriptor, setDescriptor] = useState<Float32Array | null>(null);
  const [status, setStatus] = useState("Loading models...");
  const [error, setError] = useState<string | null>(null);

  // Load face-api models
  useEffect(() => {
    async function loadModels() {
      try {
        const MODEL_URL = "/models";
        await Promise.all([
          faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
          faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
          faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
        ]);
        setModelsLoaded(true);
        setStatus("Models loaded. Requesting camera access...");
      } catch (err) {
        console.error("Failed to load models", err);
        setError("Failed to load face detection models. Are the weights in /public/models?");
      }
    }
    loadModels();
  }, []);

  // Start webcam
  useEffect(() => {
    if (!modelsLoaded) return;
    
    async function startVideo() {
      try {
        const mediaStream = await navigator.mediaDevices.getUserMedia({ 
          video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } } 
        });
        setStream(mediaStream);
        if (videoRef.current) {
          videoRef.current.srcObject = mediaStream;
        }
        setStatus("Align your face within the frame.");
        setDetecting(true);
      } catch (err) {
        console.error("Camera access denied", err);
        setError("Camera access is required for face detection.");
      }
    }
    
    startVideo();

    return () => {
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modelsLoaded]);

  // Detection loop
  useEffect(() => {
    if (!detecting || !videoRef.current || !modelsLoaded) return;

    let timeoutId: number;

    async function detect() {
      if (videoRef.current && videoRef.current.readyState === 4) {
        try {
          const detection = await faceapi
            .detectSingleFace(videoRef.current, new faceapi.TinyFaceDetectorOptions({ inputSize: 224, scoreThreshold: 0.8 }))
            .withFaceLandmarks()
            .withFaceDescriptor();

          if (detection) {
            setStatus("Face detected. Please hold still...");
            setDescriptor(detection.descriptor);
          } else {
            setStatus("No face detected. Please ensure good lighting and look directly at the camera.");
            setDescriptor(null);
          }
        } catch (err) {
          console.error("Detection error:", err);
        }
      }
      
      if (detecting) {
        timeoutId = window.setTimeout(detect, 1000); // Run every second to save CPU
      }
    }

    detect();

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [detecting, modelsLoaded]);

  const stopStream = useCallback(() => {
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      setStream(null);
    }
    setDetecting(false);
  }, [stream]);

  return {
    videoRef,
    modelsLoaded,
    stream,
    detecting,
    setDetecting,
    descriptor,
    status,
    setStatus,
    error,
    setError,
    stopStream
  };
}
