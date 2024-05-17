from datetime import datetime
from typing import List, Optional

from fastapi_amis_admin.models import IntegerChoices, Field,SQLModel,ChoiceType

class File(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, nullable=False)
    name: str = Field(title="FileName", max_length=200)
    create_time: Optional[datetime] = Field(default_factory=datetime.utcnow, title="CreateTime")
    modify_time: Optional[datetime] = Field(default_factory=datetime.utcnow,  title="ModifyTime")
    
