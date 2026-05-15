from pydantic import BaseModel, ConfigDict, Field


class TelegramUser(BaseModel):
    id: int
    is_bot: bool | None = None
    first_name: str | None = None
    last_name: str | None = None
    username: str | None = None


class TelegramChat(BaseModel):
    id: int
    type: str
    title: str | None = None
    username: str | None = None


class TelegramMessageEntity(BaseModel):
    type: str
    offset: int = 0
    length: int = 0
    url: str | None = None


class TelegramMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    message_id: int
    date: int | None = None
    chat: TelegramChat
    from_user: TelegramUser | None = Field(default=None, alias="from")
    text: str | None = None
    caption: str | None = None
    entities: list[TelegramMessageEntity] = Field(default_factory=list)
    caption_entities: list[TelegramMessageEntity] = Field(default_factory=list)


class TelegramUpdate(BaseModel):
    update_id: int
    message: TelegramMessage | None = None
    edited_message: TelegramMessage | None = None
    channel_post: TelegramMessage | None = None
    edited_channel_post: TelegramMessage | None = None

    def active_message(self) -> TelegramMessage | None:
        return self.message or self.edited_message or self.channel_post or self.edited_channel_post
