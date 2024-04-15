# Ref. https://docs.pydantic.dev/latest/concepts/pydantic_settings/#dotenv-env-support

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env')
    PROVIDER_DATABASE_URL: str

'''
settings = Settings()
print(settings.DATABASE_URL)
'''
