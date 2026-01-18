<section id="project-info">
# Xuanxue

Xuanxue는 바이브 코딩으로 작성된 Swift용 SSH 키 라이브러리입니다.

다음과 같은 기능이 있습니다: (see also: README.md)
- SSH 공개 키 불러오기
- OpenSSH 형식의 SSH 개인 키 불러오기
- 데이터 서명 및 검증

## SEE ALSO
- `dependencies/libbcrypt` - C언어 기반의 오픈 소스 bcrypt 라이브러리 구현체입니다. 이를 Package.swift에 타겟으로 추가하여 bcrypt KDF를 지원하십시오.
    - 참고로, libbcrypt 자체의 수정이 필요할 수도 있습니다. 주저 말고 수정하십시오.
- `additional-contexts` - 원격 제어 소프트웨어 'Noctiluca'에서 이 프로젝트가 필요해진 이유를 볼 수 있을 겁니다. 그리고, 이전에 구현된 코드도 확인할 수 있습니다.


## IMPLEMETATION RULES

- `swift-asn1` 패키지를 사용하여 ASN.1 파싱 및 인코딩을 수행하십시오.
- 어차피 macOS / iOS에서만 쓰일 것이므로 Apple 플랫폼 전용 프레임워크 (CryptoKit, Security) 등을 자유롭게 사용하십시오. 단, 만일을 대비하여 플랫폼 분기 (베이스 프로토콜 + #if canImport() + 구현체) 형태로 작성하는 것을 권장합니다.

- RSA 키 로드 / 서명은 Security 프레임워크, 그 외 알고리즘의 경우 CryptoKit을 사용하십시오.

- 테스트 키가 필요한 경우, `ssh-keygen`을 사용하여 키를 생성하십시오.

- 코드 구현 시에는 README.md의 예시 코드를 반드시 참조해 주십시오.
- 각 페이즈 완료 시에는 CLAUDE.md / README.md를 업데이트 해주십시오.

</section>
<section id="agent-rules">

# AGENT RULES

## 1. 언어 및 기본 규칙
- 모든 대화와 Plan은 **한국어**로 작성
- 중요한 변경 사항이 있으면 `AGENTS.md` 업데이트
- 커밋 메시지/코드 코멘트는 사무적으로 작성

## 2. 자율 개발 루프 (Autonomous Development Loop)

### 기본 행동 원칙
Claude는 **완전 자율 모드**로 동작합니다. 다음 루프를 따르세요:

1. **BUILD**: 코드를 작성/수정
2. **TEST**: `swift test` 실행
3. **ANALYZE**: 실패 시 원인 분석
4. **FIX**: 문제 수정
5. **REPEAT**: 모든 테스트 통과까지 반복
6. **COMMIT**: 성공 시 의미 있는 단위로 커밋

### 루프 종료 조건
다음 조건을 **모두** 충족하면 작업 완료:
- 모든 테스트 통과 (`swift test` 성공)
- 빌드 성공 (`swift build` 성공)
- 요청된 기능/버그 수정 완료

### 절대 하지 말 것
- 테스트 실패를 무시하고 진행
- 사용자에게 "이거 해도 될까요?" 반복 질문
- 막히면 바로 포기 → 최소 3회 다른 접근법 시도 후 보고

## 3. 커밋 컨벤션

```
[scope]: [subject]
```

예시:
- `core/keys: SSH 공개 키 파싱 구현`
- `test: Ed25519 키 서명 테스트 추가`
- `fix: RSA 키 로드 시 메모리 누수 수정`

</section>

<section id="project-todo">

# PROJECT TODO

> README.md의 FEATURES 섹션에서 추출. 자율 루프에서 참조할 체크리스트.

## Phase 1: 기반 구축 ✅
- [x] Package.swift에 swift-asn1 의존성 추가
- [x] Package.swift에 libbcrypt 타겟 추가
- [x] 기본 테스트 프레임워크 구축

## Phase 2: 키 로딩 ✅
- [x] OpenSSH Public Key 로딩
- [x] OpenSSH Private Key 로딩
  - [x] 암호화된 Private Key 지원
  - [x] bcrypt KDF 지원 (bcrypt_pbkdf 구현)
- [x] PEM Private Key 로딩

## Phase 3: 키 타입 / 알고리즘 ✅
- [x] RSA 키 지원
  - [x] `ssh-rsa`: RSA with SHA-1
  - [x] `rsa-sha2-256`: RSA with SHA-256
  - [x] `rsa-sha2-512`: RSA with SHA-512
- [x] ECDSA 키 지원
  - [x] `ecdsa-sha2-nistp256`
  - [x] `ecdsa-sha2-nistp384`
  - [x] `ecdsa-sha2-nistp521`
- [x] Ed25519 키 지원

## Phase 4: 서명 및 검증 ✅
- [x] Private Key로 데이터 서명
- [x] Public Key로 서명 검증

## Phase 5: 키 생성 ✅
- [x] RSA 키 생성
- [x] ECDSA 키 생성
- [x] Ed25519 키 생성

</section>

<section id="autonomous-loop">

# AUTONOMOUS LOOP CONFIGURATION

## Ralph Wiggum Plugin 사용법

```bash
# 설치 (최초 1회)
/plugin marketplace add anthropics/claude-code
/plugin install ralph-wiggum@claude-plugins-official

# 실행
/ralph --max-iterations 20 --completion-promise "모든 테스트 통과"

# 취소
/cancel-ralph
```

## 자율 루프 실행 시 규칙

1. **매 반복마다 `swift test` 실행**
2. **실패 시 원인 분석 후 수정** (같은 에러 3회 반복 시 다른 접근법 시도)
3. **성공 시 다음 TODO 항목으로 이동**
4. **의미 있는 단위로 커밋** (한 기능 완성 시)

## 완료 신호

모든 Phase의 TODO가 완료되면:
```
EXIT_SIGNAL: true
모든 테스트 통과
```

</section>
