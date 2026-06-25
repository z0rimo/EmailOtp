# EmailOtp

[English](README.md) | **한국어**

**ASP.NET Core용 이메일 매직코드(일회용 비밀번호) 기반 패스워드리스 로그인.**

> ⚠️ 이것은 TOTP/HOTP(`Otp.NET`, Google Authenticator 등)가 **아닙니다**. 공유 비밀키도,
> 시간 윈도우 알고리즘도 없습니다. 대신 서버가 **짧은 수명의 코드를 생성·전달(이메일/SMS 등)하고,
> 그 코드의 전체 수명주기를 데이터베이스에서 관리**합니다 — Slack, Notion 등이 쓰는
> "이메일로 6자리 코드를 보냈습니다" 패턴입니다.

## 왜 필요한가

ASP.NET Core에는 "이메일로 로그인 코드를 보내는" 1급 기능이 없습니다. 직접 구현하면 보통 정작
중요한 부분을 놓칩니다: **원자적 일회성 소비**, **동시성 환경에서의 무차별 대입 시도 제한**,
**작은 코드 공간의 안전한 해싱**. EmailOtp는 딱 그 부분만 패키지화했고, 그 이상은 하지 않습니다 —
사용자 생성이나 토큰 발급은 **하지 않습니다**. 코드 검증은 그 사람이 해당 받은편지함을 통제한다는
사실만 증명할 뿐이며, 그다음(사용자 조회/생성, JWT·쿠키 발급)은 애플리케이션의 몫으로 남습니다.

## 모델

EmailOtp는 **`(email, purpose)` 슬롯당 active challenge를 1개만** 유지합니다. 새 코드는 먼저
`PendingDelivery`로 저장되고 **발송이 성공한 뒤에야 active로 승격**되며 이전 코드를 supersede합니다 —
그래서 한 슬롯에 살아있는 코드가 둘이 되지 않고, 전달되지 않은 코드는 검증 자체가 불가능합니다.
challenge 수명주기: `PendingDelivery → Active → (Verified | Superseded | Expired | Locked)`,
또는 `PendingDelivery → DeliveryFailed`. filtered unique index와 낙관적 동시성 토큰이 동시 요청
환경에서도 single-active 불변식을 보장합니다.

## 보안

- 코드는 평문이나 단순 SHA-256이 아니라 **HMAC-SHA256 + 서버 측 pepper**로 저장됩니다.
  6자리 코드는 경우의 수가 100만개뿐이라, 키 없는 해시는 DB 유출 시 손쉽게 역산됩니다.
  pepper(DB **밖**에, 예를 들어 환경변수로 보관)가 이를 차단합니다.
- **일회성**: 검증된 코드는 원자적으로(낙관적 동시성) 소비되어, race 상황에서도 재사용·이중소비가
  불가능합니다.
- **시도 제한**: 오답은 compare-and-set으로 카운트되며, 상한 도달 즉시 challenge가 **Locked** 됩니다.
  동시 제출 환경에서도 상한이 유지됩니다.
- **crash-safe 발급 / 코드 미잔존**: 새 코드는 `PendingDelivery`로 저장되어 발송 성공 전까지 검증
  불가능하며, 성공 시에만 atomic하게 active로 승격됩니다. 활성화 전 크래시나 발송 실패는 이전 코드를
  그대로 두고 미전달 코드를 절대 활성화하지 않습니다. 버려진 pending 행은 만료되어 `PurgeExpiredAsync`로
  제거됩니다. 발송이 너무 느려 pending 코드의 전달 deadline이 지났다면, 활성화는 거부되어(pending이 만료)
  더 새롭고 유효한 active 코드를 supersede하지 않습니다.
- `FailureReason`**뿐 아니라 `RemainingAttempts`도** 사용자에게 그대로 노출하지 마세요 — 응답은 generic하게
  유지합니다(아래 참고). 둘 다 logging / metrics / 내부 처리 용도로만 사용하세요.

> **레이트 리미팅은 소비자 책임입니다.** challenge별 시도 제한은 *하나의* 코드 추측만 막을 뿐, 요청 스팸,
> 반복적인 challenge 교체, 분산 남용, 엔드포인트 플러딩은 막지 못합니다. 공개 전에 request·verify 양쪽
> 엔드포인트에 email·IP 및 광범위한 남용 신호 기준의 애플리케이션 레벨 throttling을 추가하세요.

## 설치

```bash
dotnet add package EmailOtp                 # 저장소 독립 코어
dotnet add package EmailOtp.EntityFramework # EF Core 저장소 어댑터
```

대상 프레임워크: **net8.0+**.

## 빠른 시작 (ASP.NET Core + EF Core)

**1. DbContext에 엔티티를 매핑합니다:**

```csharp
using EmailOtp.EntityFramework;

public class AppDbContext : DbContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.AddEmailOtp();   // EmailOtpChallenges 테이블 추가
}
```

**2. 전달 구현(`IEmailOtpSender`)을 작성합니다:**

```csharp
public sealed class SmtpOtpSender : IEmailOtpSender
{
    public Task SendAsync(string email, string code, string purpose, CancellationToken ct = default)
    {
        // 원하는 방식으로 `code`를 `email`로 전송
        return Task.CompletedTask;
    }
}
```

**3. 등록합니다 (pepper는 DB가 아니라 환경변수/시크릿 저장소에서):**

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(connectionString));

builder.Services
    .AddEmailOtp(o => o.Secret = builder.Configuration["EMAILOTP_PEPPER"]!)
    .UseEntityFramework<AppDbContext>()
    .AddSender<SmtpOtpSender>();
```

**4. 엔드포인트에서 사용합니다:**

```csharp
app.MapPost("/auth/request-code", async (string email, IEmailOtpService otp) =>
{
    await otp.RequestAsync(email);
    return Results.Ok();   // 주소 존재 여부를 노출하지 않습니다
});

app.MapPost("/auth/verify-code", async (string email, string code, IEmailOtpService otp) =>
{
    var result = await otp.VerifyAsync(email, code);
    if (!result.Succeeded)
        return Results.BadRequest("Invalid or expired code.");   // generic하게 유지

    // result.FailureReason / RemainingAttempts는 로깅/메트릭 용도로는 쓸 수 있지만,
    // 호출자에게 그대로 노출하지 마세요.

    // ↓ 여기부터는 애플리케이션의 몫 — EmailOtp는 여기서 멈춥니다
    // var user = await users.GetOrCreateAsync(result.Email);
    // var jwt  = tokens.Issue(user);
    return Results.Ok();
});
```

`EmailOtpChallenges` 테이블 생성을 잊지 마세요 (EF 마이그레이션, 또는 개발 환경에서는 `EnsureCreated`).

## 설정 (`EmailOtpOptions`)

| 옵션                              | 기본값       | 비고 |
|-----------------------------------|--------------|------|
| `Secret`                          | *(필수)*     | HMAC pepper. 16바이트 이상. DB 밖에 보관. |
| `CodeLength`                      | `6`          | 4~12 자리. |
| `Expiry`                          | `10분`       | 코드 수명. |
| `MaxAttempts`                     | `5`          | challenge가 잠기기 전까지 허용 오답 횟수. |
| `NormalizeEmailToLowerInvariant`  | `true`       | 정규화 시 이메일 소문자 변환. |
| `MaxEmailLength`                  | `320`        | 더 긴 이메일은 거부. |
| `MaxPurposeLength`                | `64`         | 더 긴 purpose는 거부. |

잘못된 설정(예: pepper 누락/길이 부족)은 `ValidateOnStart`로 startup에서 즉시 실패합니다.

## Purpose (다용도)

`RequestAsync`/`VerifyAsync`는 `purpose`(기본값 `"login"`)를 받습니다. 같은 이메일이라도 용도별로
독립적인 코드를 보유할 수 있습니다 — `"login"`, `"email-change"`, `"password-reset"` 등.

## Provider 및 저장소 참고

- **provider 지원 수준:** SQLite는 **integration-tested**(전체 스위트, 실 DB, 동시성 스트레스 테스트 포함).
  SQL Server는 **live-tested**(실 서버에서 request/verify 플로우 검증, 동시성 스트레스 테스트는 미실시).
  **그 외 provider는 테스트 전까지 미지원** — 동작할 수는 있으나 미검증입니다.
- **동시 발급:** activation은 기존 코드 supersede + 새 코드 promote를 **한 트랜잭션 안에서 원자적으로** 수행합니다
  (실패 시 rollback이 기존 active를 복원 → 교체 실패가 슬롯을 코드 없는 상태로 남기지 않음). SQLite에서는
  트랜잭션이 **`BEGIN IMMEDIATE`** 라서 BEGIN 시점에 write 소유권을 잡고, 같은 슬롯에 대한 두 activation이
  겹쳐도 거기서 직렬화되어 shared→exclusive 락 업그레이드 deadlock을 피하며, **delivery deadline 검사도 write
  소유권 확보 후 평가**됩니다. SQLite에서 (진짜 병렬 + rollback 테스트로) 검증됐으며, SQL Server live 사용도 검증됐습니다.
  다만 동시 activation 스트레스 테스트(row-lock + 일반 트랜잭션 환경에서 deadline 검사가 락 대기 중에도
  유지되는지)는 **미실시**입니다. 인식된 transient-lock/concurrency 충돌은 bounded retry(jitter
  포함), 지속적 충돌은 transient `EmailOtpConcurrencyException`으로 표면화됩니다(요청 재시도).
- **단일 active 슬롯**은 `(Email, Purpose) WHERE [Status] = 0` **filtered unique index**로 보장됩니다.
  partial/filtered unique index를 지원하는 provider가 필요합니다 — SQLite·SQL Server는 작성한 그대로
  생성됩니다. 그 외 provider는 CI 대상이 아닙니다. PostgreSQL은 partial index는 되지만 식별자 quoting이
  달라, provider에 맞는 필터를 넘기세요:
  ```csharp
  modelBuilder.AddEmailOtp(activeIndexFilter: "\"Status\" = 0"); // 예: PostgreSQL
  ```
- **동시성 토큰:** `RowVersion`은 **application-managed** 토큰으로, store가 매 write마다 회전시킵니다.
  SQL Server의 auto-update `rowversion`에 **의존하지 않으므로**, 그것이 없는 provider(SQLite 등)에서도
  낙관적 동시성이 동일하게 동작합니다.
- **`PurgeExpiredAsync(now)`** 는 **감사 로그 보존용이 아니라 maintenance cleanup**입니다. status와 무관하게
  `ExpiresAt <= now`인 모든 challenge를 삭제합니다(만료된 active 행 포함). 만료되지 않은 행은 유지됩니다.
  백그라운드 작업에서 주기적으로 호출하고, 이력이 필요하면 별도로 감사 로그를 남기세요.

## 확장성

모든 것이 합리적인 기본 구현을 가진 인터페이스입니다. 기본 구현 클래스는 internal이며 `AddEmailOtp()` /
`UseEntityFramework()`가 대신 등록합니다. 교체하려면 해당 인터페이스의 사용자 구현을 등록하세요(나중 등록이 우선).

| 인터페이스                  | 내장 기본 구현                            | 교체 예시 |
|-----------------------------|-------------------------------------------|-----------|
| `IEmailOtpStore`            | EF Core (`UseEntityFramework<TContext>`)  | Dapper, Redis, … |
| `IEmailOtpSender`           | *(직접 제공)*                             | SMTP, SES, SMS, 콘솔 |
| `IEmailOtpCodeGenerator`    | 숫자 코드                                 | 영숫자, 사용자 지정 길이 |
| `IEmailOtpHasher`           | HMAC-SHA256 + pepper                       | 사용자 지정 KDF |
| `IEmailOtpEmailNormalizer`  | trim + lower-invariant                    | 사용자 지정 정규화 |

`IEmailOtpStore`에는 만료 row 정기 정리를 위한 `PurgeExpiredAsync(now)`도 있습니다.

## 라이선스

MIT
