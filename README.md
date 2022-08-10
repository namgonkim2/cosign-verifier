# cosign-verifier
Exercises to create a cosign-based mutating admission controller

## What it is?
A program based on the golang language for validating signatures on images signed with cosign.  
cosign으로 서명한 이미지에 대해 서명이 유효한지 검사하기 위한 golang 언어 기반의 프로그램입니다.
  
This is the code that wrote the process of finding the signature image for use in the validation webhook for the image signed with cosign.  
cosign으로 서명한 이미지에 대해 validation webhook에 사용하기 위해 서명 이미지를 찾는 과정을 작성한 코드입니다.  

There are library pkgs required for webhooks in sigstore/cosign. Using them you can check images signed with cosign.  
sigstore/cosign에서 webhook에 필요한 라이브러리 pkg들이 존재합니다. 그들을 사용하면 cosign으로 서명된 이미지를 검사할 수 있습니다.  

## How to use
* The cosign key must be stored in Kubernetes **(Not Keyless)**.  
  Use ```cosign generate-key-pair k8s://<namespace>/<secret>```.  
* 쿠버네티스에 cosign key가 저장되어 있어야 합니다.**(Keyless가 아닙니다.)**  
    ```cosign generate-key-pair k8s://<namespace>/<secret>``` 를 이용하세요.
* Save the required information in cosignConfig.yaml
* cosignConfig.yaml에 필요한 정보를 저장합니다.
  ```yaml
  kubeConfig: <your_k8s_kubeConfig_dir> (ex. /home/namgon/.kube/config)
  registry: <your_registry> (ex. harbor.localhost_ip.nip.io)
  image: <image> (ex. library/alpine)
  tag: <tag> (ex. latest)
  signer: <cosign annotation value that key is 'signer'> (ex. namgon)
  secretKeyRef: k8s://<namespace>/<cosign-key-secret> (ex. k8s://cosign/cosign-key-secret)
  ```
```bash
go run main.go
```

## Reference
* https://github.com/sigstore/policy-controller/
* https://github.com/sigstore/cosign
* https://github.com/dlorenc/cosigned