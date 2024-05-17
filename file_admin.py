from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import Body, Depends
from fastapi_amis_admin import admin
from fastapi_amis_admin.admin import AdminApp
from fastapi_amis_admin.amis import (
    Action,
    ActionType,
    Dialog,
    Form,
    FormItem,
    Page,
    PageSchema,
    SchemaNode,
    SizeEnum,
    TableColumn,
    TableCRUD,
)
from fastapi_amis_admin.crud.schema import (
    BaseApiOut,
    CrudEnum,
    ItemListSchema,
    Paginator,
)
import uuid
from fastapi_amis_admin.crud.utils import ItemIdListDepend
from fastapi_amis_admin.models.fields import Field
from fastapi_amis_admin.utils.pydantic import (
    ModelField,
    create_model_by_model,
    model_fields,
)
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel, validator
from starlette.requests import Request
from typing_extensions import Annotated, Literal
import os
import csv

class CrawledFileAdmin(admin.PageAdmin):
    page_schema = PageSchema(label=_("Crawled File"), icon="fa fa-file")
    page_path = "/"
    router_prefix = "/files"

    class FileModel(BaseModel):
        id: str = Field(..., title=_("File ID"))
        file_name: str = Field(..., title=_("File Name"))
        modified_at: str = Field(..., title=_("Modified At"))
        
        @classmethod
        def parse_file(cls, file: dict):
            return cls(**file)
        
    def __init__(self, app: "AdminApp"):
        super().__init__(app)
        self.schema_update = create_model_by_model(
            self.FileModel,
            "FilesUpdate",
            include={"file_name"},
            set_none=True,
        )
        self.paginator = Paginator(perPageMax=100)

    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        headerToolbar = [
            "reload",
            "bulkActions",
            {"type": "columns-toggler", "align": "right"},
            {"type": "drag-toggler", "align": "right"},
            {"type": "pagination", "align": "right"},
            {
                "type": "tpl",
                "tpl": _("SHOWING ${items|count} OF ${total} RESULT(S)"),
                "className": "v-middle",
                "align": "right",
            },
        ]
        
        page.body = TableCRUD(
            api=f"get:{self.router_path}/list",
            autoFillHeight=True,
            headerToolbar=headerToolbar,
            filterTogglable=True,
            filterDefaultVisible=False,
            syncLocation=False,
            keepItemSelectionOnPageChange=True,
            footerToolbar=[
                "statistics",
                "switch-per-page",
                "pagination",
                "load-more",
                "export-csv",
            ],
            columns=await self.get_list_columns(request),
            itemActions=await self.get_actions_on_item(request),
            # bulkActions=await self.get_actions_on_bulk(request),
        )
        return page

    async def get_list_columns(self, request: Request) -> List[TableColumn]:
        columns = []
        update_fields = model_fields(self.schema_update)
        for modelfield in model_fields(self.FileModel).values():
            column = self.site.amis_parser.as_table_column(modelfield, quick_edit=modelfield.name in update_fields)
            if column:
                columns.append(column)
        return columns

    async def get_actions_on_item(self, request: Request) -> List[Action]:
        actions = [
            # await self.get_job_action(request, bulk=False, action="resume"),
            # await self.get_job_action(request, bulk=False, action="pause"),
            await self.append_to_original_data(request, bulk=False),
            # await self.get_job_action(request, bulk=False, action="remove"),
        ]
        return list(filter(None, actions))

    # async def get_actions_on_bulk(self, request: Request) -> List[Action]:
    #     bulkActions = [
    #         await self.get_job_action(request, bulk=True, action="resume"),
    #         await self.get_job_action(request, bulk=True, action="pause"),
    #         await self.get_job_action(request, bulk=True, action="remove"),
    #     ]
    #     return list(filter(None, bulkActions))

    async def get_update_form(self, request: Request, bulk: bool = False):

        api = f"{self.router_path}/item/" + ("${ids|raw}" if bulk else "$id")
        fields = model_fields(self.schema_update).values()
        return Form(
            api=api,
            name=CrudEnum.update,
            body=[await self.get_form_item(request, field, action=CrudEnum.update) for field in fields],
            submitText=None,
            trimValues=True,
        )

    # async def get_update_action(self, request: Request, bulk: bool = False) -> Optional[Action]:
    #     return ActionType.Dialog(
    #         icon="fa fa-plus-circle",
    #         tooltip=_("Update"),
    #         dialog=Dialog(
    #             title=_("Update"),
    #             size=SizeEnum.lg,
    #             body=await self.get_update_form(request, bulk=bulk),

    #         ),
    #     )

    async def append_to_original_data(self, request: Request, bulk: bool = False):
        return ActionType.Dialog(
            icon="fa fa-plus-circle",
            tooltip=_("Add to root data"),
            dialog=Dialog(
                title=_("Add to root data"),
                size=SizeEnum.lg,
                body=await self.get_update_form(request, bulk=bulk),
            ),
        )

    async def get_form_item(self, request: Request, modelfield: ModelField, action: CrudEnum) -> Union[FormItem, SchemaNode]:
        is_filter = action == CrudEnum.list
        return self.site.amis_parser.as_form_item(modelfield, is_filter=is_filter)
    
    def get_file_info(self):
        files_info = []
        directory_path = "file"
        # Iterate over each file in the directory
        for file_name in os.listdir(directory_path):
            # Get the full file path
            file_path = os.path.join(directory_path, file_name)
            
            # Check if it is a file (not a directory)
            if os.path.isfile(file_path):
                # Get the last modified time
                modified_time = os.path.getmtime(file_path)
                
                # Convert it to a readable format
                readable_time = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S')
                
                # Append the file name and its modified time to the list
                files_info.append({"id": file_name.replace(".csv", ""),"file_name": file_name, "modified_at": readable_time})

        # Print the array to verify
        return files_info
    def read_csv(self, file_path):
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            rows = list(reader)
        return rows

    def write_csv(self, file_path, rows):
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerows(rows)
            
    def append_unique_rows_with_id(self, source_file, target_file):
    # Read the rows from both source and target files
        source_rows = self.read_csv(source_file)
        target_rows = self.read_csv(target_file)
        
        # Check if either file is empty
        if not source_rows:
            raise ValueError(f"The source CSV file {source_file} is empty.")
        if not target_rows:
            raise ValueError(f"The target CSV file {target_file} is empty.")

        # Combine headers and data, assuming first row as header
        source_header, source_data = source_rows[0], source_rows[1:]
        target_header, target_data = target_rows[0], target_rows[1:]

        # Ensure headers match
        if source_header != target_header:
            raise ValueError("CSV files have different headers")

        # Determine the next ID to use
        existing_ids = [int(row[0]) for row in target_data if row[0].isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        # Use a set for checking duplicates based on the data rows (excluding ID column)
        target_set = set(map(tuple, [row[1:] for row in target_data]))

        # Append unique rows from source to target data with new IDs
        for row in source_data:
            if tuple(row[1:]) not in target_set:
                target_data.append([next_id] + row[1:])
                target_set.add(tuple(row[1:]))
                next_id += 1

        # Write the combined data back to the target file
        combined_rows = [target_header] + target_data
        self.write_csv(target_file, combined_rows)
            
    def register_router(self):
        @self.router.get(
            "/list",
            response_model=BaseApiOut[ItemListSchema[self.FileModel]],
            include_in_schema=True,
        )
        async def get_files(paginator: Annotated[self.paginator, Depends()]):  # type: ignore
            files = self.get_file_info()
            start = (paginator.page - 1) * paginator.perPage
            end = paginator.page * paginator.perPage
            data = ItemListSchema(items=[self.FileModel.parse_file(file) for file in files[start:end]])
            data.total = len(files) if paginator.show_total else None
            return BaseApiOut(data=data)

        @self.router.post(
            "/item/{item_id}",
            response_model=BaseApiOut[List[self.FileModel]],
            include_in_schema=True,
        )
        async def add_file_to_root_data(
            item_id: ItemIdListDepend,
            action: Literal["update"] = "update",
            data: Annotated[self.schema_update, Body()] = None,  # type: ignore
        ):
            files = self.get_file_info()
            file_models = [self.FileModel.parse_file(file) for file in files]
        
            selected_files = [file for file in file_models if file.id in item_id]
            if action == "update":
                for file in selected_files:
                    
                    type = file.file_name.split("_")[0]
                    self.append_unique_rows_with_id(f"file/{file.file_name}", f"data/{type}_data.csv")
                    file.file_name = data.file_name  # Update the file_name if provided

            return BaseApiOut(data=selected_files)

        return super().register_router()